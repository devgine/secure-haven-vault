# Configurer Keycloak pour le SSO OIDC

Ce guide décrit la procédure côté Keycloak pour connecter l'application via OIDC :
création et configuration du client, puis création des groupes utilisés pour le mapping
des permissions vers les coffres.

Il s'adresse à l'administrateur du realm Keycloak. La partie « côté application »
(activation du fournisseur, mapping groupes → coffres/rôles) se fait ensuite dans la
console d'administration de l'application, onglet SSO.

Prérequis : Keycloak 21+ (21, 22, 23, 24, 25, 26 supportés), un realm dédié à
l'application (par ex. `sentinel`), et l'URL publique de l'application
(par ex. `https://vault.example.com`).

---

## 1. Créer et configurer le client

### 1.1 Création

1. Connectez-vous à la console d'administration Keycloak et sélectionnez le realm cible.
2. Menu **Clients** → **Create client**.
3. Écran *General Settings* :
   - **Client type** : `OpenID Connect`
   - **Client ID** : un identifiant stable, par ex. `sentinel-vault` — c'est la valeur
     à reporter dans le champ « Client ID » de la console admin de l'application.
   - **Name** : libre, par ex. `Sentinel Vault`.
4. Cliquez **Next**. Écran *Capability config* :
   - **Client authentication** : `On` (client confidentiel — le serveur de l'application
     échange le code d'autorisation côté serveur avec le secret).
   - **Authorization** : `Off`.
   - **Authentication flow** : cochez **Standard flow** (Authorization Code). Laissez
     *Direct access grants*, *Implicit*, *Service accounts* et *Device Authorization*
     décochés — l'application n'utilise que le flux standard.
5. Cliquez **Next**. Écran *Login settings* :

   | Champ | Valeur |
   |---|---|
   | **Root URL** | `https://vault.example.com` |
   | **Home URL** | `https://vault.example.com` |
   | **Valid redirect URIs** | `https://vault.example.com/api/public/oidc/callback` |
   | **Valid post logout redirect URIs** | `https://vault.example.com/*` |
   | **Web origins** | `https://vault.example.com` |

   > L'URI de redirection doit être **exacte** (schéma, hôte, chemin). Toute
   > différence provoque une erreur `invalid_redirect_uri` au retour de Keycloak.
   > En développement local, ajoutez aussi
   > `http://localhost:3000/api/public/oidc/callback`.

6. Cliquez **Save**.

### 1.2 Récupérer le secret client

1. Dans la fiche du client, onglet **Credentials**.
2. Copiez la valeur **Client Secret**. Elle sera saisie dans la console admin de
   l'application, qui la chiffre sous la clé maître avant stockage. Ne la transmettez
   par aucun autre canal que la console admin.

### 1.3 Exposer les groupes dans les jetons

Le mapping des permissions repose sur les groupes Keycloak, qui doivent apparaître
dans le claim `groups` des jetons. Par défaut Keycloak ne les émet pas : il faut
ajouter un mapper.

1. Ouvrez le client → onglet **Client scopes** → cliquez le scope dédié
   `<client-id>-dedicated`.
2. **Add mapper** → **By configuration** → **Group Membership**.
3. Configurez :
   - **Name** : `groups`
   - **Token Claim Name** : `groups`
   - **Full group path** : `Off` (recommandé : le claim contiendra `admins` plutôt
     que `/admins` — mettez `On` uniquement si vous distinguez des groupes de même
     nom dans des parents différents, et utilisez alors le chemin complet dans les
     mappings de l'application).
   - Laissez **Add to ID token**, **Add to access token** et **Add to userinfo**
     sur `On`.
4. **Save**.

### 1.4 Vérifier l'émetteur (issuer)

L'« Issuer URL » à renseigner dans l'application est :

```text
https://<hote-keycloak>/realms/<realm>
```

Exemple : `https://sso.example.com/realms/sentinel`.

L'application résout les endpoints via la découverte OIDC
(`<issuer>/.well-known/openid-configuration`) : ce document doit être joignable
**depuis le serveur de l'application** (pas seulement depuis le navigateur).
Vérifiez avec :

```bash
curl -s https://<hote-keycloak>/realms/<realm>/.well-known/openid-configuration | head
```

Si Keycloak est derrière un reverse proxy, assurez-vous que l'URL d'émetteur
annoncée dans le document de découverte correspond à l'URL publique (option
`KC_HOSTNAME` côté Keycloak), sinon la validation de l'émetteur échouera.

### 1.5 Scopes

L'application demande `openid email profile groups`. Assurez-vous que les client
scopes `email` et `profile` restent assignés au client (c'est le cas par défaut).
L'email est utilisé comme identifiant de compte côté application : activez
**Email** et une méthode de vérification appropriée sur les utilisateurs fédérés.

---

## 2. Créer les groupes

Les groupes Keycloak sont la source d'appartenance que l'application traduit en
appartenance aux coffres via ses mappings (groupe IdP → coffre + rôle).

### 2.1 Création

1. Menu **Groups** → **Create group**.
2. Nommez le groupe de façon explicite et stable, par ex. :
   - `vault-prod-admins` → mapping vers le coffre « Production » en rôle ADMIN
   - `vault-prod-editors` → coffre « Production » en rôle EDITOR
   - `vault-prod-readers` → coffre « Production » en rôle VIEWER
3. Répétez par coffre à provisionner. Pour des arborescences, créez des groupes
   parents (par ex. `vault` / `vault/prod-admins`) et alignez l'option
   *Full group path* du mapper (§1.3) avec le format utilisé dans les mappings.

Conventions recommandées :

- Préfixez les groupes par le nom de l'application (`vault-…`) pour les distinguer
  des groupes d'autres applications dans le même realm.
- Le **nom du groupe est la clé de jointure** : un renommage côté Keycloak casse le
  mapping existant jusqu'à mise à jour côté application. Préférez des noms stables
  et sans espaces.
- Un groupe n'impose aucun rôle par défaut côté application : c'est le mapping
  créé dans la console admin (groupe → coffre + rôle) qui décide.

### 2.2 Affecter les utilisateurs

1. Menu **Users** → sélectionnez l'utilisateur → onglet **Groups**.
2. **Join Group** → cochez le ou les groupes → **Join**.

Un utilisateur peut appartenir à plusieurs groupes mappés sur le même coffre : le
rôle le plus élevé (OWNER > ADMIN > EDITOR > VIEWER) est retenu.

### 2.3 Vérifier que les groupes remontent

Avant de finaliser, validez que le claim est bien émis :

1. Client → onglet **Client scopes** → onglet **Evaluate**.
2. Sélectionnez un utilisateur de test, générez le jeton, et vérifiez dans
   l'onglet *Generated access token* / *Generated ID token* la présence de :

```json
"groups": ["vault-prod-admins", "vault-prod-readers"]
```

Si le claim est absent : revérifiez le mapper *Group Membership* (§1.3) et
l'appartenance de l'utilisateur au groupe.

---

## 3. Finaliser côté application

1. Console admin de l'application → onglet **SSO** :
   - Nom du fournisseur (affiché sur le bouton de connexion), Issuer URL (§1.4),
     Client ID et Client Secret (§1.1, §1.2).
   - Mode de permissions : `local`, `oidc` ou `hybrid` selon que les appartenances
     aux coffres sont gérées manuellement, uniquement via les groupes, ou les deux.
   - Activez le fournisseur.
2. Créez les mappings : pour chaque groupe Keycloak, associez le coffre cible et le
   rôle (OWNER/ADMIN/EDITOR/VIEWER). Le nom saisi doit correspondre **exactement**
   au contenu du claim `groups` (nom simple ou chemin complet selon *Full group path*).
3. Testez avec un compte de test membre d'un groupe mappé : à la première connexion
   SSO, le compte est provisionné et les appartenances sont appliquées ; elles sont
   réévaluées à chaque connexion.

## Dépannage

| Symptôme | Cause probable |
|---|---|
| `invalid_redirect_uri` au retour de Keycloak | URI de redirection non déclarée ou différente (§1.1) |
| Échec « émetteur invalide » | Issuer URL différente de celle du document de découverte (§1.4) |
| Connexion OK mais aucun coffre attribué | Claim `groups` absent (§1.3, §2.3) ou nom de groupe ne correspondant pas au mapping |
| Bouton SSO absent de la page de connexion | Fournisseur non activé dans la console admin |
