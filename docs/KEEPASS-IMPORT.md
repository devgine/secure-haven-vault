# Import KeePass

Sentinel Vault peut importer une base KeePass existante dans votre coffre
personnel ou dans un coffre d'équipe où vous avez le droit de créer des secrets.

## Formats pris en charge

| Format | Statut | Détail |
| --- | --- | --- |
| KDBX 4 (KeePass 2.35+) | Pris en charge, testé | AES-KDF et Argon2d / Argon2id |
| KDBX 3.1 (KeePass 2.x) | Pris en charge, testé | AES-KDF |
| KDB (KeePass 1.x) | **Non pris en charge** | Convertissez la base : KeePass 2 → *Fichier → Enregistrer sous → .kdbx* |

Bibliothèque utilisée : [`kdbxweb`](https://github.com/keeweb/kdbxweb) (MIT),
navigateur uniquement, complétée par `hash-wasm` (MIT) pour Argon2. Aucun
algorithme cryptographique KeePass n'est réimplémenté par l'application.

Les tests automatisés (`bunx vitest run`) génèrent de vraies bases KDBX 3 et 4
(mot de passe, fichier clé, mot de passe + fichier clé, base vide, base
corrompue, mauvais identifiants) — aucun secret réel n'est utilisé.

## Modèle de sécurité

Le fichier `.kdbx` est déchiffré **entièrement dans le navigateur**. Ne quittent
jamais le poste de l'utilisateur :

- le fichier `.kdbx` chiffré ;
- le mot de passe maître ;
- le fichier clé ;
- les clés dérivées ;
- les données déchiffrées tant que l'import n'est pas confirmé.

Après confirmation, seules les entrées **sélectionnées** sont envoyées au
serveur (métadonnées + valeurs), en HTTPS, puis immédiatement chiffrées en
AES-256-GCM avec la DEK du coffre avant écriture. Aucune valeur n'est écrite en
clair en base, ni dans les journaux.

### Limites honnêtes du nettoyage mémoire

JavaScript ne permet pas d'effacer la mémoire de façon garantie. À l'annulation,
à l'erreur ou à la fin de l'import, l'application supprime ses références au mot
de passe, au fichier clé et à la base déchiffrée, révoque les URL temporaires et
remet le composant à zéro. Le ramasse-miettes du navigateur reste toutefois le
seul à décider du moment de la libération réelle : des copies peuvent subsister
temporairement dans le tas, et un vidage mémoire du processus navigateur ou une
extension malveillante peuvent y accéder. Aucune donnée n'est en revanche placée
dans `localStorage`, `sessionStorage`, un cache applicatif ou un gestionnaire
d'état persistant.

## Procédure

1. **Destination** — tableau de bord → *Importer un coffre KeePass*, ou page
   d'un coffre → *Importer KeePass*. Seuls les coffres où vous avez le droit
   d'importer sont proposés ; le serveur revérifie ce droit à chaque lot.
2. **Fichier** — glisser-déposer ou sélection du `.kdbx`, fichier clé
   facultatif. Le contenu réel est validé (signature binaire), pas l'extension.
3. **Déverrouillage local** — mot de passe maître (masqué par défaut, bouton
   afficher/masquer, indicateur Verr. Maj) et/ou fichier clé. En cas d'échec, un
   message générique est affiché et les tentatives sont limitées localement.
4. **Prévisualisation** — nombre de groupes, entrées, pièces jointes, champs
   personnalisés, entrées avec TOTP, entrées ignorées et avertissements.
   Arborescence à cocher, recherche, tout (dé)sélectionner. Les valeurs
   sensibles restent masquées.
5. **Options** — dossier racine (`Import KeePass — {date}`), stratégie de
   doublons et critères de détection.
6. **Confirmation** puis **import par lots** avec progression.
7. **Rapport final** téléchargeable.

## Champs importés

| KeePass | Sentinel Vault |
| --- | --- |
| Groupe | Dossier (arborescence préservée) |
| Title | Nom du secret |
| UserName | Nom d'utilisateur |
| Password | Champ « Mot de passe » (sensible) |
| URL | URL |
| Notes | Description (champ sensible si la note était protégée) |
| Tags | Tags |
| Champs personnalisés | Champs personnalisés (le caractère protégé est conservé) |
| Pièces jointes | Pièces jointes chiffrées |
| TOTP (`otp`, `TOTP Seed`/`TOTP Settings`) | Champ TOTP chiffré (secret, émetteur, compte, algorithme, chiffres, période) |
| Created / Last modified | Dates d'origine conservées |
| Icône | Conservée sous forme d'identifiant lorsque disponible |

Les champs inconnus sont conservés comme champs personnalisés plutôt que
supprimés. Un champ protégé n'est jamais transformé en donnée publique.

Non pris en charge : historique des versions KeePass, entrées de la corbeille
KeePass, règles de génération de mot de passe, associations de fenêtres
(auto-type), déverrouillage par challenge-response matériel (YubiKey).

## Doublons

Détection sur des **métadonnées uniquement** (nom, nom d'utilisateur, URL,
dossier de destination — combinaison configurable). Les mots de passe ne sont
jamais comparés. Stratégies : ignorer, importer une copie, remplacer, fusionner
les champs manquants. Remplacement et fusion exigent la permission
`secret.update` ; l'entrée remplacée est mise à la corbeille (récupérable), pas
supprimée.

## Pièces jointes et limites

| Limite | Valeur par défaut |
| --- | --- |
| `MAX_KEEPASS_ATTACHMENT_SIZE` | 10 Mo par pièce jointe |
| `MAX_KEEPASS_TOTAL_IMPORT_SIZE` | 200 Mo par import |
| `MAX_KEEPASS_ENTRY_COUNT` | 10 000 entrées |

Une pièce jointe hors limite est ignorée : l'entrée est importée sans elle et un
avertissement explicite est affiché dans le rapport.

## Échec et reprise

L'import est traité par lots de 50 entrées, chaque entrée dans sa propre
transaction. Chaque entrée porte une clé déterministe (UUID KeePass) unique par
job : relancer un import interrompu reprend là où il s'est arrêté sans créer de
doublon, et une double soumission n'écrit qu'une seule fois.

## Journal et rapport

Le journal d'audit enregistre l'utilisateur, le coffre, la date, la stratégie,
les compteurs et le statut. Il ne contient jamais de mot de passe, de secret
TOTP, de valeur de champ, de pièce jointe, de clé ni de contenu du fichier
KeePass. Le rapport téléchargeable suit les mêmes règles.
