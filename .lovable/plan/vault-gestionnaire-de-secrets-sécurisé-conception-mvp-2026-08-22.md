# Vault — Gestionnaire de secrets sécurisé (conception + MVP)

Application de gestion de secrets type Bitwarden/1Password, orientée personnel + équipes, construite sur TanStack Start (React 19, TypeScript, Tailwind) avec Lovable Cloud (PostgreSQL + Auth) comme backend managé. Ce document présente l'architecture demandée, puis un découpage en phases. Le développement commence après validation.

## A. Architecture

- **Frontend** : TanStack Start (React 19 + TS + Tailwind v4 + shadcn). Routes publiques : `/` (landing), `/auth`. Routes protégées sous `_authenticated/` : coffre, workspaces, générateurs, audit, `/admin/*`, settings.
- **Backend** : `createServerFn` (RPC typé) pour toute la logique applicative — le navigateur ne touche jamais la base directement sauf via RLS stricte ; routes serveur `/api/public/*` pour OIDC callback, `/health`, `/ready`.
- **Base de données** : PostgreSQL (Lovable Cloud). RLS activée partout + contrôles d'autorisation systématiques côté serveur dans chaque fonction (défense en profondeur : un `workspaceId` fourni par le client n'est jamais fiable).
- **Authentification** : locale email/password via Lovable Cloud Auth (hash bcrypt côté serveur, jamais MD5/SHA) ; OIDC générique (Keycloak, Auth0, Okta, Entra ID, Google) en authorization code flow implémenté dans des routes serveur. Architecture prête pour MFA/TOTP/WebAuthn (point d'extension dans le flow de session).
- **Chiffrement** : envelope encryption AES-256-GCM côté serveur (voir section E).
- **RBAC** : permissions atomiques regroupées en rôles (section D), vérifiées dans chaque server fn.
- **Docker** : `Dockerfile` + `docker-compose.yml` (app + PostgreSQL, volumes, healthchecks, exemple reverse proxy) livrés en phase 6. Note honnête : la plateforme Lovable héberge la base managée ; la config Docker prépare le self-hosting mais nécessitera d'y brancher votre propre instance PostgreSQL/Auth via variables d'environnement.

## B. Threat Model

| Menace | Protection |
|---|---|
| Compromission de la base | Secrets chiffrés (AES-256-GCM), clé maître hors BDD (secret d'environnement), DEK par workspace wrappées. Un dump SQL seul ne révèle rien. |
| Vol de session | Sessions expirantes, verrouillage manuel + auto du coffre (5/15/30/60 min), ré-authentification extensible pour actions sensibles, redirection vers `/auth` à l'expiration. |
| XSS | Échappement React par défaut, CSP stricte (headers serveur), valeurs de secrets jamais injectées dans le HTML sans action explicite. |
| CSRF | RPC same-origin + jeton bearer (pas de cookies d'action cross-site), SameSite sur cookies. |
| Injection SQL | ORM/PostgREST paramétré, validation Zod stricte côté serveur sur chaque entrée. |
| Utilisateur malveillant / escalade | Chaque server fn re-vérifie : authentification → appartenance au workspace → permission exacte. Super admin ≠ accès crypto : il administre sans pouvoir lire les coffres (ni les Personal Vaults). |
| Fuite de logs | Audit logs sans aucune valeur en clair (métadonnées uniquement), secrets jamais loggés ni dans les erreurs. |
| Brute force | Rate limiting sur login et endpoints sensibles, protection anti-énumération. |
| Compromission admin | Séparation administration plateforme / autorisation cryptographique ; audit de toutes les actions admin. |

## C. Modèle de données (tables principales)

```text
auth.users ── profiles (id, display_name, avatar, prefs, lock_timeout)
auth.users ── user_roles (user_id, role: SUPER_ADMIN | USER)      [table séparée, jamais sur profiles]
workspaces (id, name, is_personal, owner_id, disabled, deleted_at)
workspace_members (workspace_id, user_id, role: OWNER|ADMIN|EDITOR|VIEWER)
encryption_keys (workspace_id, wrapped_dek, key_version)          [DEK wrappée par la clé maître]
secrets (id, workspace_id, type, name, username, url, description,
         tags[], favorite, expires_at, notify_before_days,
         created_by/updated_by/created_at/updated_at, deleted_at)
secret_fields (id, secret_id, label, field_type, ciphertext, iv)  [valeurs chiffrées]
secret_versions (id, secret_id, version, changed_by, changed_at, meta)
audit_logs (id, ts, user_id, workspace_id, action, target, ip, user_agent, result)
oidc_providers (id, name, issuer, endpoints, client_id,
                client_secret_ciphertext, scopes, enabled)
oidc_group_mappings (id, provider_id, oidc_group, workspace_id, role, app_role)
```

Métadonnées (nom, username, URL, tags) en clair pour la recherche ; **toutes les valeurs sensibles** (passwords, tokens, clés, notes, champs custom "secret") chiffrées dans `secret_fields`.

## D. Permission Model

Permissions atomiques : `workspace.read/update/delete`, `member.read/invite/update/delete`, `secret.create/read/reveal/copy/update/delete`, `audit.read`, `oidc.manage`, `users.manage`, `admin.access`.

| Rôle | Permissions |
|---|---|
| SUPER_ADMIN (plateforme) | `users.manage`, `oidc.manage`, `audit.read`, `admin.access`, gestion workspaces — **aucune** permission `secret.*` sur les coffres des autres |
| OWNER (workspace) | toutes permissions du workspace + transfert de propriété |
| ADMIN | membres (si OIDC inactif), CRUD secrets, reveal |
| EDITOR | create/update/read/reveal secrets |
| VIEWER | read + reveal si politique du workspace l'autorise |

Helper serveur unique `requirePermission(userId, workspaceId, permission)` appelé dans chaque fonction. Le mode « permissions gérées par OIDC » désactive l'édition locale des membres/rôles (local / OIDC / hybride).

## E. Encryption Model

- **Quoi** : toutes valeurs sensibles de `secret_fields` + `client_secret` OIDC.
- **Comment** : AES-256-GCM. À la création d'un workspace : génération d'une **DEK 256 bits** (CSPRNG `crypto.getRandomValues` côté serveur), wrappée par la **clé maître** et stockée dans `encryption_keys`. Chaque champ : IV aléatoire unique + tag d'authentification GCM.
- **Clé maître** : secret d'environnement serveur (`MASTER_ENCRYPTION_KEY`), jamais en base, jamais en code, jamais côté client.
- **Où déchiffré** : uniquement côté serveur, dans la server fn, **après** contrôle RBAC ; le client reçoit la valeur en clair seulement sur action explicite (Reveal/Copy), jamais dans les listes.
- **Abstraction KMS** : interface `KeyProvider { wrapKey(), unwrapKey() }` — implémentation `EnvKeyProvider` au MVP, `VaultKmsProvider` / `AwsKmsProvider` enfichables ensuite sans changer le schéma.
- **Limite assumée (transparence)** : le serveur peut déchiffrer (modèle « server-side encryption », pas zero-knowledge type Bitwarden). Le zero-knowledge avec clé dérivée du mot de passe est une évolution possible ultérieure ; l'envelope encryption ci-dessus est le bon socle et répond à l'exigence « jamais en clair au repos ».

## F. OIDC Flow

1. L'utilisateur clique « Se connecter avec SSO » → `/api/public/oidc/authorize` (state + PKCE stockés).
2. Redirection vers l'IdP (Keycloak…) → retour sur `/api/public/oidc/callback?code=…`.
3. Serveur : échange du code (token endpoint), validation de l'ID token via JWKS de l'issuer (signature, iss, aud, exp).
4. Extraction des claims : `groups`, `realm_access.roles`, `resource_access.*`.
5. Application des `oidc_group_mappings` : ex. `/password-manager/dev` → workspace *Development* + rôle EDITOR ; `/password-manager/admin` → SUPER_ADMIN. Synchronisation à chaque login (ajouts/retraits).
6. Création/mise à jour de l'utilisateur (auto-provisioning), ouverture de session applicative, audit `oidc.login`.
7. `client_secret` stocké chiffré (DEK plateforme), jamais renvoyé au frontend.

Admin : page **Settings > Authentication > OIDC** (enable, issuer, client id/secret, endpoints, scopes, redirect/logout URI) + page **OIDC Mapping** (groupe OIDC → workspace + rôle), avec exemple Keycloak pré-rempli.

## G. Structure du projet

```text
src/routes/            # /, /auth, _authenticated/ (vault, w/$id, generator,
                       #   audit, admin/*, settings), api/public/ (health, oidc/*)
src/lib/crypto.server.ts          # AES-256-GCM, KeyProvider, envelope
src/lib/permissions.ts            # matrice rôle → permissions
src/lib/*.functions.ts            # server fns (secrets, workspaces, admin, oidc)
src/components/        # UI vault (liste, détail masqué, reveal/copy, generator…)
src/components/ui/     # shadcn
tests/                 # vitest : authz, isolation cross-workspace, crypto, générateurs
Dockerfile, docker-compose.yml
```

## H. Plan de développement (phases)

1. **Fondations** — design system (thème dark/light pro, type Linear/Vercel), auth locale, tables RBAC (profiles, user_roles, workspaces, members), premier SUPER_ADMIN, garde `_authenticated`.
2. **Coffre** — envelope encryption AES-256-GCM + `encryption_keys`, Personal Vault auto à l'inscription, CRUD secrets + templates (Login, API Key, Token+alerte expiration, SSH, Database, Note, Custom), masquage/Reveal/Copy (clipboard auto-clear), suppression avec corbeille.
3. **Organisation** — recherche (nom/username/URL/tags/type), tags, favoris, récents, versions/historique, générateurs CSPRNG (password + robustesse, Base64, HEX 16/32/64/custom, UUID v4, token avec préfixe).
4. **Audit & Admin** — audit logs complets, `/admin` (dashboard, users, workspaces, auth), verrouillage du coffre (manuel + inactivité), expiration session → `/auth`.
5. **OIDC** — config provider, flow complet Keycloak, mapping groupes → rôles/workspaces, modes local/OIDC/hybride.
6. **Durcissement & livraison** — CSP/security headers, rate limiting, tests d'autorisation (dont « user workspace A ≠ secret workspace B »), `/health` + `/ready`, Dockerfile + docker-compose, doc sauvegarde/restauration.

Je commencerai par les phases 1–2 (fondations + coffre chiffré fonctionnel) dès validation, puis j'enchaînerai.
