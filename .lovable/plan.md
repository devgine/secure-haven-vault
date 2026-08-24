# Import KeePass (.kdbx) — audit préalable et proposition

Aucune modification de code n'a été faite. Voici l'audit demandé et la proposition, en attente de ta validation.

## 0. Audit de l'existant

**Cryptographie** (`src/lib/crypto.server.ts`) : chiffrement enveloppe côté serveur. Une DEK AES-256 par coffre, générée par CSPRNG, enveloppée AES-256-GCM par une clé maître dérivée de `MASTER_ENCRYPTION_KEY` (jamais en base). Chaque valeur de champ est chiffrée AES-256-GCM avec IV aléatoire, format `v1.<iv>.<ct>`. Verdict : **l'architecture supporte l'import sans aucune modification cryptographique**. Les valeurs déchiffrées dans le navigateur seront rechiffrées avec la DEK du coffre de destination avant écriture. Je ne toucherai pas au modèle crypto.

**Permissions** (`src/lib/vault.server.ts`, `permissions.ts`) : toute écriture passe par `requireWorkspacePermission(userId, workspaceId, permission)` qui relit le rôle en base (pas de RLS, pas de confiance au client), refuse les coffres désactivés/supprimés. Verdict : **suffisant**, l'import réutilisera `secret.create` / `secret.update` et une nouvelle permission `folder.create`.

**Journalisation** (`audit.server.ts`) : métadonnées uniquement, pas de valeurs. Compatible.

**Limite identifiée** : le modèle n'a **ni dossiers, ni pièces jointes, ni champ TOTP typé**. L'arborescence KeePass ne peut pas être préservée en l'état — c'est la principale évolution du modèle de données.

## A. Bibliothèque proposée

- **kdbxweb 2.1.1** — licence **MIT**, dépendances `@xmldom/xmldom` + `fflate` (toutes deux MIT, pures JS). C'est la bibliothèque du client KeeWeb, référence de fait côté navigateur. Publication la plus récente : 2021 — le format KDBX étant figé, elle est stable plutôt qu'abandonnée ; c'est un point que je te signale honnêtement.
- **hash-wasm 4.12.0** (MIT, sans dépendances, maintenu 2024) pour fournir l'implémentation Argon2d/Argon2id que kdbxweb exige pour KDBX 4.
- Aucun algorithme cryptographique KeePass ne sera réimplémenté.

**Formats** : `.kdbx` KeePass 2.x, **KDBX 3.1** (AES-KDF) et **KDBX 4 / 4.1** (Argon2d, Argon2id, ChaCha20). Je vérifierai chacun par un test automatisé avec des bases fictives générées à la volée ; ce qui ne passe pas les tests ne sera pas annoncé comme supporté. **`.kdb` (KeePass 1.x) : non supporté** — message explicite invitant à convertir en `.kdbx`. Déverrouillage : mot de passe, fichier clé (XML v1/v2 et binaire/hash), ou les deux. Les bases à clé Windows-account / YubiKey afficheront une erreur claire, sans envoi réseau.

## B. Schéma du traitement local

```text
navigateur                                        | serveur
--------------------------------------------------|------------------------------
fichier .kdbx (ArrayBuffer, jamais uploadé)        |
+ mot de passe maître (kdbxweb ProtectedValue)     |
+ fichier clé (ArrayBuffer)                        |
      -> kdbxweb.Kdbx.load()  (Web Crypto + wasm)  |
      -> arbre déchiffré EN MÉMOIRE seulement      |
      -> prévisualisation masquée, sélection       |
      -> effacement (zéro-fill + déréférencement)  |
                    | confirmation explicite        |
                    v                               |
        POST par lots : titre, username, url, notes,|-> vérif. permission serveur
        champs, tags, dates, TOTP, pièces jointes   |-> chiffrement AES-256-GCM
        (valeurs en clair, TLS, jamais persistées   |   sous la DEK du coffre
         telles quelles)                            |-> audit métadonnées
```

Ne quittent **jamais** le navigateur : le fichier `.kdbx` chiffré, le mot de passe maître, le fichier clé, les clés dérivées, et les données avant confirmation. Vérifié par un test réseau Playwright qui inspecte toutes les requêtes.

## C. Données envoyées au serveur (après confirmation)

Par lot : `importJobId`, `workspaceId`, `folderPath`, stratégie de doublons, et pour chaque entrée : nom, username, url, notes, tags, dates KeePass, champs (label/type/sensible/valeur), TOTP (secret + émetteur/algo/chiffres/période), pièces jointes (nom, mime, taille, contenu base64), plus un `clientKey` (UUID déterministe local) pour l'idempotence.

## D. Mapping des champs

| KeePass | Application |
|---|---|
| Groupe (arborescence) | `secret_folders` (nouvelle table, arbre par coffre) |
| Title | `secrets.name` |
| UserName | `secrets.username` |
| Password | champ `password`, sensible |
| URL | `secrets.url` |
| Notes | `secrets.description` (ou champ `textarea` sensible si protégé) |
| Tags | `secrets.tags` |
| Champs personnalisés | `secret_fields` — `isSensitive` = flag « protégé » KeePass |
| Attachments | `secret_attachments` (chiffrées) |
| TOTP (`otp` / `TimeOtp-*`) | champ `totp`, sensible, métadonnées conservées |
| Created / LastModified | `secrets.created_at` / colonnes `source_created_at`, `source_modified_at` |
| Icône | `secrets.icon` (index KeePass → icône Lucide, best effort) |
| Champs inconnus | conservés en champs personnalisés, jamais supprimés |

Un champ protégé KeePass reste sensible côté application. Le type de secret est déduit (LOGIN, SSH_KEY, DATABASE, SECURE_NOTE…) avec repli sur CUSTOM.

## E. Stratégie de doublons

Détection **côté serveur** sur une clé configurable parmi nom / username / URL / dossier cible (jamais sur les mots de passe, jamais en clair côté serveur). Stratégies : ignorer, créer une copie, remplacer, fusionner les champs manquants, décider entrée par entrée. Remplacement et fusion : confirmation explicite, re-vérification de `secret.update`, version récupérable conservée dans `secret_versions` (ancien enregistrement en soft-delete), audit sans contenu.

## F. Modifications du modèle de données

Nouvelle migration `db/init.sql` (idempotente) :
- `secret_folders` (id, workspace_id, parent_id, name, position) + `secrets.folder_id`
- `secret_attachments` (secret_id, filename, mime, size, ciphertext, created_at) — chiffrées sous la DEK du coffre
- `secrets.icon`, `secrets.source_created_at`, `secrets.source_modified_at`
- `import_jobs` (id, user_id, workspace_id, status, counters, strategy) et `import_items` (job_id, client_key unique, secret_id, status) → reprise après erreur, idempotence, protection anti-double-soumission
- permission `folder.create` ajoutée à la matrice RBAC (OWNER/ADMIN/EDITOR)

## G. Limites techniques (annoncées honnêtement)

- **Nettoyage mémoire JS non garanti** : on peut zéro-remplir les `Uint8Array` et déréférencer, mais les `string` JS sont immuables et le GC est non déterministe. Documenté tel quel.
- Fichiers volumineux : tout est en mémoire ; avertissement au-delà de ~20 Mo.
- Limites configurables : `MAX_KEEPASS_ATTACHMENT_SIZE` (10 Mo), `MAX_KEEPASS_TOTAL_IMPORT_SIZE` (100 Mo), `MAX_KEEPASS_ENTRY_COUNT` (5000). Dépassement d'une pièce jointe : entrée importée sans elle + avertissement.
- Historique des entrées et corbeille KeePass : non importés (signalés dans le rapport).
- Transaction : atomique **par lot** (50 entrées), pas sur l'import entier — d'où les jobs reprenables.

## H. Risques de sécurité et parades

| Risque | Parade |
|---|---|
| Fuite du mot de passe maître via un rapport d'erreur | rapporteur d'erreurs désactivé sur le composant d'import, jamais de secret dans un `throw` |
| Import dans un coffre non autorisé via requête forgée | `requireWorkspacePermission` à chaque lot, jamais confiance au client |
| Élévation de privilège via données importées | rôles jamais dérivés du fichier |
| Doublons massifs après échec | `client_key` unique + `import_items` |
| Zip-bomb / pièce jointe hostile | limites de taille, type MIME neutralisé, jamais exécutée ni indexée |
| Fuite dans les logs | audit = compteurs et métadonnées uniquement, tests dédiés |
| Attaque par force brute locale | limitation de tentatives côté client, sans télémétrie |

## Plan de développement (après ta validation)

1. Migration modèle de données + permission `folder.create`
2. Fonctions serveur d'import (jobs, lots, doublons, pièces jointes, audit)
3. Bibliothèques + module de lecture KDBX en navigateur (worker isolé)
4. Assistant d'import en 9 étapes (création de coffre ou coffre existant)
5. Tests (bases fictives, permissions, réseau, logs, reprise) + documentation

**J'attends ta validation avant de commencer.** Je ne modifierai pas l'architecture cryptographique : elle reste inchangée, l'import s'y branche.
