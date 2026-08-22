# Secure Haven Vault

Je veux créer une application web sécurisée de gestion de secrets, comparable dans son usage à KeePass, Bitwarden ou 1Password, mais orientée à la fois vers les usages personnels et les équipes.
L'application doit permettre de stocker de manière sécurisée tous types d'informations sensibles :
mots de passe ;
identifiants / credentials ;
clés SSH privées et publiques ;
tokens API ;
API keys ;
secrets applicatifs ;
certificats ;
clés de chiffrement ;
chaînes de connexion ;
variables d'environnement ;
codes de récupération ;
notes sécurisées ;
et plus généralement n'importe quelle donnée sensible.
Le projet doit être pensé comme une véritable application de production, avec une architecture sécurisée, modulaire et maintenable.
1. Principe fondamental de sécurité
La sécurité est la priorité absolue.
Les secrets ne doivent jamais être stockés en clair dans la base de données.
Je veux que l'architecture soit conçue selon les bonnes pratiques modernes de gestion de secrets.
Prévoir au minimum :
chiffrement des secrets au repos ;
chiffrement des communications en TLS ;
clés de chiffrement séparées des données ;
aucune clé sensible écrite en dur dans le code source ;
aucun secret sensible dans les logs ;
protection contre les attaques XSS, CSRF, SQL/NoSQL injection et brute force ;
gestion sécurisée des sessions ;
cookies HttpOnly, Secure, SameSite ;
Content Security Policy ;
rate limiting ;
protection contre les tentatives répétées de connexion ;
validation stricte des données côté serveur ;
expiration des sessions ;
audit des opérations sensibles.
Pour le chiffrement des secrets, utiliser une méthode moderne telle que AES-256-GCM ou un mécanisme équivalent offrant chiffrement + authentification.
Utiliser une stratégie de type envelope encryption :
chaque secret ou workspace peut utiliser une Data Encryption Key ;
cette clé chiffre les données ;
la Data Encryption Key est elle-même protégée par une clé maître ;
la clé maître ne doit jamais être stockée directement dans la base applicative.
Prévoir une architecture qui permet ultérieurement d'intégrer un véritable KMS tel que :
HashiCorp Vault ;
AWS KMS ;
Azure Key Vault ;
Google Cloud KMS.
Ne jamais afficher les secrets par défaut.
Ils doivent être masqués dans l'interface et révélés seulement lorsqu'un utilisateur clique explicitement sur une action comme :
Afficher le secret
Prévoir également :
bouton Copier ;
copie temporaire dans le presse-papiers ;
possibilité de masquer à nouveau automatiquement le secret ;
ne jamais exposer inutilement les secrets dans les réponses API.
2. Authentification
L'application doit avoir plusieurs méthodes d'authentification.
Super administrateur
Il doit exister un rôle :
SUPER_ADMIN
Le super administrateur possède les droits globaux sur la plateforme :
gérer les utilisateurs ;
gérer les workspaces ;
gérer la configuration OIDC ;
consulter les journaux d'audit ;
gérer les rôles ;
gérer les paramètres globaux.
Attention : même le SUPER_ADMIN ne doit pas nécessairement pouvoir lire automatiquement tous les secrets en clair.
Prévoir une architecture permettant de distinguer :
administration de la plateforme ;
autorisation cryptographique d'accès aux secrets.
Cette séparation est importante pour la sécurité.
Utilisateurs standards
Les utilisateurs peuvent se connecter avec :
username/password ou email/password ;
OIDC.
Prévoir également une architecture compatible avec une future authentification MFA / TOTP / WebAuthn.
Les mots de passe utilisateurs doivent être hashés avec un algorithme robuste comme :
Argon2id ;
éventuellement bcrypt si nécessaire.
Ne jamais utiliser MD5, SHA1 ou SHA256 seul pour stocker les mots de passe.
3. OIDC / SSO
L'application doit supporter OpenID Connect.
Je veux pouvoir connecter des Identity Providers comme :
Keycloak ;
Auth0 ;
Okta ;
Azure Entra ID ;
Google Workspace ;
tout serveur compatible OIDC.
Créer dans l'administration une page :
Settings > Authentication > OIDC
avec les paramètres :
Enable OIDC ;
Issuer URL ;
Client ID ;
Client Secret ;
Authorization Endpoint si nécessaire ;
Token Endpoint si nécessaire ;
UserInfo Endpoint ;
scopes ;
redirect URI ;
logout URI.
Les credentials OIDC sensibles doivent eux-mêmes être stockés de manière sécurisée.
4. Mapping des groupes et rôles OIDC
Je veux pouvoir gérer les permissions directement depuis mon Identity Provider.
Exemple avec Keycloak :
un utilisateur peut appartenir aux groupes :
password-manager-admin
workspace-dev
workspace-production
workspace-marketing
L'application doit pouvoir lire les claims OIDC contenant :
groups ;
roles ;
realm roles ;
client roles.
Créer un système de mapping configurable.
Exemple :
OIDC Group:
/password-manager/admin
→ Application Role:
SUPER_ADMIN
OIDC Group:
/password-manager/dev
→ Workspace:
Development
→ Role:
EDITOR
OIDC Group:
/password-manager/prod
→ Workspace:
Production
→ Role:
VIEWER
La synchronisation des permissions doit pouvoir être effectuée automatiquement lors de la connexion de l'utilisateur.
Prévoir différents modes :
permissions gérées localement ;
permissions gérées depuis OIDC ;
éventuellement mode hybride.
5. Workspaces
L'application doit permettre de créer plusieurs workspaces.
Exemples :
Personnel
Development
Production
Entreprise
Client A
Client B
Chaque utilisateur ne doit voir que les workspaces auxquels il a accès.
L'isolation des données entre les workspaces doit être strictement appliquée côté backend et jamais uniquement dans l'interface frontend.
Un utilisateur ne doit pas pouvoir accéder au contenu d'un autre workspace simplement en modifiant une URL ou un ID dans une requête API.
le super admin ne doit pouvoir accéder à aucun workspace et surtout a aucun espace personnel des utilisateurs
6. Coffre personnel
Chaque utilisateur doit automatiquement disposer d'un espace :
Personal Vault
Cet espace lui appartient exclusivement.
Par défaut :
seul l'utilisateur peut accéder à ce coffre ;
aucun autre utilisateur ne peut le voir ;
il n'apparaît pas comme workspace partagé.
Le Personal Vault doit utiliser exactement le même niveau de chiffrement que les workspaces collaboratifs.
7. Gestion des membres des workspaces
Pour chaque workspace, permettre d'ajouter plusieurs utilisateurs.
Prévoir au minimum les rôles :
OWNER
ADMIN
EDITOR
VIEWER
Permissions proposées :
OWNER
accès complet ;
gérer le workspace ;
gérer les membres (seulement si pas de OIDC);
gérer les permissions (seulement si pas de OIDC);
créer/modifier/supprimer les secrets ;
voir les secrets ;
transférer la propriété.
ADMIN
gérer les membres selon les permissions autorisées (seulement si pas de OIDC);
créer/modifier/supprimer les secrets ;
voir les secrets.
EDITOR
créer des secrets ;
modifier des secrets ;
voir les secrets.
VIEWER
consulter les entrées ;
afficher les secrets si la politique du workspace l'autorise ;
aucune modification.
Construire le système RBAC de manière extensible afin de pouvoir ajouter de nouvelles permissions plus tard.
8. Structure d'un secret
Chaque entrée du coffre doit avoir au minimum :
ID ;
workspace ;
type ;
name ;
username ;
secret/password/token ;
URL ;
description ;
tags ;
favorite ;
created_at ;
updated_at ;
created_by ;
updated_by.
Aucun des champs fonctionnels suivants ne doit être obligatoire :
username ;
URL ;
description ;
tags.
Seul le minimum technique nécessaire à la création de l'entrée peut être obligatoire.
9. Types de secrets
Prévoir différents templates.
Login
username ;
password ;
URL.
API Key
API key ;
API secret ;
endpoint ;
description.
Token
token ;
expiration ;
endpoint.
Pour les tokens ayant une date d’expiration, prévoir une fonctionnalité d’alerte par main avant expiration
A la création ou la modification du token, l'utilisateur peut choisir de programmer une alerte X temps avant expiration pour le renouvellement
SSH Key
username ;
hostname ;
port ;
private key ;
public key ;
passphrase.
Database
hostname ;
port ;
database ;
username ;
password ;
connection string.
Secure Note
title ;
encrypted content.
Custom
Permettre à l'utilisateur de créer autant de champs personnalisés qu'il souhaite.
Chaque champ personnalisé doit pouvoir être défini comme :
texte standard ;
secret ;
URL ;
username ;
password ;
date ;
textarea.
10. Générateur de mots de passe et secrets
Créer un générateur intégré.
L'utilisateur doit pouvoir définir :
longueur ;
lettres minuscules ;
lettres majuscules ;
chiffres ;
symboles ;
exclusion des caractères ambigus ;
caractères personnalisés.
Exemple :
Length:
32
Options:
A-Z
a-z
0-9
symbols
Afficher une estimation de la robustesse du mot de passe.
Ajouter également plusieurs générateurs techniques.
Random password
Exemple :
Yt9#kL2!pQ8@Vm4$
Base64
Permettre de générer une quantité configurable de données aléatoires puis de les encoder en Base64.
Exemple :
openssl rand -base64 32
équivalent applicatif.
HEX
Permettre de générer :
HEX16 ;
HEX32 ;
HEX64 ;
taille personnalisée.
Exemple :
7e5f94c08c...
UUID
Support :
UUID v4 ;
éventuellement UUID v7.
API Token
Token aléatoire sécurisé configurable.
Exemple :
sk_xxxxxxxxxxxxxxxxx
Possibilité de définir un préfixe personnalisé.
Tous les générateurs doivent impérativement utiliser un Cryptographically Secure Pseudo-Random Number Generator fourni par l'environnement d'exécution.
Ne jamais utiliser Math.random() pour générer des secrets.
11. Interface utilisateur
Je veux une interface moderne, professionnelle, minimaliste et claire.
Inspirations UX :
1Password ;
Bitwarden ;
KeePassXC ;
Linear ;
Vercel.
Layout principal :
Sidebar
Personal Vault
Workspaces
Favorites
Recent
Password Generator
Audit Log si autorisé
Administration si autorisé
Settings
Header
recherche ;
workspace actuel ;
profil utilisateur ;
verrouillage du coffre.
Zone principale
Liste des secrets avec :
icône ;
nom ;
type ;
username ;
URL ;
tags ;
date de modification.
Lorsqu'une entrée est ouverte :
afficher les informations mais garder les valeurs sensibles masquées.
Exemple :
Password:
••••••••••••••••
Actions :
Reveal ;
Copy ;
Edit ;
Delete.
12. Recherche
Ajouter une recherche rapide.
Recherche par :
nom ;
username ;
URL ;
description ;
tags ;
type.
Attention à ne pas créer d'index ou de logs contenant accidentellement les valeurs des secrets.
13. Tags et organisation
Permettre :
tags ;
favoris ;
dossiers ou collections si pertinent ;
filtres ;
tri.
Exemple de tags :
production
database
ssh
aws
client
development
14. Historique
Conserver un historique sécurisé des modifications.
Exemple :
Secret updated
User:
john@example.com
Date:
2026-08-22 14:32
Le système doit pouvoir montrer :
qui a modifié l'entrée ;
quand ;
quelle opération a été effectuée.
Éviter d'enregistrer la valeur en clair des secrets dans les logs.
15. Audit Logs
Créer un véritable système d'audit.
Événements à enregistrer :
login ;
logout ;
failed login ;
secret created ;
secret viewed ;
secret copied ;
secret modified ;
secret deleted ;
workspace created ;
workspace deleted ;
user added ;
user removed ;
role changed ;
OIDC login ;
configuration changed.
Pour chaque événement :
timestamp ;
user ;
workspace ;
action ;
source IP si disponible ;
user agent si pertinent ;
résultat success/failure.
Les journaux d'audit ne doivent jamais contenir le secret en clair.
16. Sécurité lors de la suppression
Pour les suppressions sensibles :
demander une confirmation ;
permettre éventuellement une corbeille ;
définir une période de récupération configurable.
Prévoir également un système de suppression définitive.
17. Verrouillage du coffre
Ajouter un bouton :
Lock Vault
Après verrouillage :
les secrets ne sont plus accessibles ;
une nouvelle authentification ou validation est nécessaire.
Prévoir un verrouillage automatique après une durée d'inactivité configurable.
Exemple :
5 minutes ;
15 minutes ;
30 minutes ;
1 heure.
18. API Backend
Le frontend ne doit jamais avoir un accès direct non sécurisé à la base de données.
Toutes les opérations sensibles doivent passer par une API backend.
Chaque endpoint doit vérifier :
utilisateur authentifié ;
workspace demandé ;
appartenance de l'utilisateur au workspace ;
permission demandée ;
politique de sécurité.
Ne jamais faire confiance à un workspaceId reçu du frontend sans effectuer les contrôles d'autorisation côté serveur.
19. Architecture
Je veux une architecture moderne.
Frontend recommandé :
React ;
Next.js ;
TypeScript ;
Tailwind CSS ;
composants modernes et accessibles.
Backend :
Node.js ;
TypeScript ;
API REST ou architecture adaptée.
Base de données :
PostgreSQL de préférence.
ORM possible :
Prisma.
Mais l'architecture doit rester modulaire afin de pouvoir changer certains composants ultérieurement.
20. Modèle de données
Prévoir au minimum les entités :
User
Workspace
WorkspaceMember
Role
Permission
Secret
SecretField
SecretVersion
Tag
AuditLog
OIDCProvider
OIDCMapping
UserSession
Exemple de relations :
User
→ Personal Vault
User
→ WorkspaceMember
WorkspaceMember
→ Workspace
WorkspaceMember
→ Role
Workspace
→ Secret
Secret
→ SecretField
Secret
→ SecretVersion
21. Permissions fines
Construire le backend autour de permissions et non uniquement autour de rôles codés en dur.
Exemple :
workspace.read
workspace.update
workspace.delete
member.read
member.invite
member.update
member.delete
secret.create
secret.read
secret.reveal
secret.copy
secret.update
secret.delete
audit.read
oidc.manage
users.manage
Les rôles doivent simplement regrouper plusieurs permissions.
22. Page Administration
Créer une interface /admin.
Sections :
Dashboard
nombre d'utilisateurs ;
workspaces ;
secrets ;
connexions récentes ;
événements de sécurité.
Users
créer (si oidc pas activé);
désactiver  (si oidc pas activé);
supprimer  (si oidc pas activé);
modifier  (si oidc pas activé);
consulter les workspaces  (si oidc pas activé);
rôles  (si oidc pas activé);
Workspaces
créer ;
activer/désactiver ; (si le workspace est désactiver, son accès est coupé pour tous le monde)
administrer ;
gérer les membres  (si oidc pas activé);
Authentication
Local Authentication ;
OIDC.
OIDC Mapping
Mapping :
OIDC Group / Role
→
Workspace + Application Role
Audit Logs
Recherche et filtres.
23. Configuration OIDC Keycloak
Prévoir dès le départ un exemple spécifique pour Keycloak.
Le token peut par exemple contenir :
{
  "preferred_username": "john",
  "email": "john@example.com",
  "groups": [
    "/password-manager/dev",
    "/password-manager/production"
  ],
  "realm_access": {
    "roles": [
      "password-manager-user"
    ]
  }
}
L'application doit permettre de créer des règles comme :
OIDC group:
/password-manager/dev

Workspace:
Development

Role:
EDITOR
et :
OIDC group:
/password-manager/production

Workspace:
Production

Role:
VIEWER
24. API future / CLI
Préparer l'architecture afin que l'on puisse ajouter ultérieurement :
CLI ;
extension navigateur ;
application mobile ;
application desktop ;
API publique ;
intégration CI/CD ;
Kubernetes ;
Terraform ;
GitHub Actions ;
GitLab CI.
Exemples futurs :
vault-cli get production/database/password
ou :
vault-cli inject production/my-app
Mais ne développe pas encore ces fonctions si elles ralentissent le MVP.
Prépare simplement l'architecture pour pouvoir les intégrer proprement.
25. Docker
L'application doit pouvoir être self-hosted.
Créer une configuration Docker permettant de lancer au minimum :
frontend ;
backend ;
PostgreSQL.
Prévoir les variables d'environnement nécessaires.
Ne jamais mettre de credentials par défaut dangereux dans la configuration de production.
Préparer également :
health checks ;
migrations de base de données ;
volumes persistants ;
configuration pour reverse proxy.
L'application devra pouvoir être déployée derrière :
Nginx ;
Traefik ;
Kubernetes Ingress.
26. Health endpoints
Créer :
/health
et éventuellement :
/ready
Ils ne doivent retourner aucune information sensible.
27. Sauvegarde
Prévoir une stratégie permettant de sauvegarder la base de données.
Attention :
une sauvegarde de la base ne doit pas permettre de retrouver facilement les secrets sans les clés cryptographiques nécessaires.
Documenter les éléments nécessaires à une restauration complète :
database ;
configuration ;
clés cryptographiques ;
paramètres OIDC.
28. Tests
Créer des tests pour les fonctionnalités critiques.
Tests prioritaires :
authentification ;
autorisation ;
isolation entre workspaces ;
Personal Vault ;
chiffrement/déchiffrement ;
permissions ;
OIDC ;
mapping des groupes ;
génération sécurisée de mots de passe ;
tentative d'accès à un workspace non autorisé.
Ajouter notamment un test qui confirme :
User A membre du Workspace A ne peut jamais récupérer un secret appartenant au Workspace B.
Même en appelant directement l'API.
29. Critères de sécurité importants
Ne jamais :
stocker un mot de passe utilisateur en clair ;
stocker un secret métier en clair ;
écrire un secret dans les logs ;
envoyer toutes les données sensibles au frontend sans nécessité ;
utiliser Math.random() pour générer un mot de passe ;
faire confiance uniquement aux contrôles frontend ;
utiliser des IDs comme mécanisme de sécurité ;
stocker une master encryption key dans la même table que les secrets ;
exposer les clés privées SSH dans les logs ou dans les erreurs ;
exposer le client secret OIDC dans le frontend.
30. UX de sécurité
Lorsqu'un utilisateur copie un secret :
afficher une notification :
Secret copied to clipboard
Prévoir si possible un nettoyage automatique du clipboard après une durée configurable lorsque le navigateur le permet.
Lorsqu'un secret est affiché :
permettre de le masquer automatiquement après quelques secondes.
Pour les opérations très sensibles, l'architecture doit permettre ultérieurement de demander une nouvelle authentification.
Quand la session utilisateur expire suite a une longue inactivité, redirection direct vers l'écran de connexion
31. Dashboard utilisateur
Après connexion :
afficher :
Personal Vault ;
workspaces accessibles ;
secrets récents ;
favoris ;
recherche ;
générateur de mots de passe.
Ne jamais montrer les workspaces auxquels l'utilisateur n'appartient pas.
32. Design responsive
L'application doit fonctionner sur :
desktop ;
tablette ;
mobile.
Desktop reste la cible principale.
33. Dark mode
Prévoir :
Light mode ;
Dark mode ;
System mode.
34. Première version à développer
Je veux que tu commences par construire un MVP fonctionnel mais déjà sécurisé contenant :
authentification locale ;
SUPER_ADMIN ;
utilisateurs ;
Personal Vault ;
workspaces ;
membres de workspace ;
RBAC ;
création/modification/suppression de secrets ;
chiffrement des secrets ;
générateur de mots de passe ;
générateur Base64 ;
générateur HEX ;
générateur UUID ;
recherche ;
tags ;
favoris ;
audit logs ;
interface d'administration ;
configuration OIDC ;
connexion Keycloak ;
mapping OIDC Groups → Workspace Roles ;
Docker ;
PostgreSQL ;
tests des règles d'autorisation.
35. Méthode de travail attendue
Avant de développer tout le projet, commence par me présenter :
A. Architecture
Explique :
frontend ;
backend ;
base de données ;
authentification ;
chiffrement ;
gestion des clés ;
RBAC ;
OIDC.
B. Threat Model
Identifie les principales menaces :
compromission de la base ;
vol de session ;
XSS ;
CSRF ;
utilisateur malveillant ;
escalade de privilège ;
fuite de logs ;
attaque sur l'API ;
compromission d'un administrateur.
Explique les protections prévues.
C. Modèle de données
Présente les principales tables et leurs relations.
D. Permission Model
Présente les rôles et permissions.
E. Encryption Model
Explique précisément :
quelles données sont chiffrées ;
où elles sont chiffrées ;
comment elles sont déchiffrées ;
où les clés sont conservées ;
comment une future intégration KMS/Vault sera possible.
F. OIDC Flow
Explique :
User → Identity Provider → OIDC callback → validation token → récupération des claims → mapping groups/roles → création/mise à jour de l'utilisateur → attribution des workspaces → création de session
G. Structure du projet
Présente les dossiers et composants principaux.
H. Plan de développement
Découpe l'implémentation en phases.
Seulement ensuite, commence le développement.
36. Principe final
Ce projet doit être traité comme une application de sécurité et non comme une simple application CRUD.
À chaque décision technique, privilégie dans cet ordre :
sécurité ;
isolation des données ;
simplicité de l'architecture ;
maintenabilité ;
expérience utilisateur ;
performances.
Si une fonctionnalité demandée crée une faiblesse de sécurité, ne l'implémente pas naïvement : explique le problème et propose une architecture plus sûre.

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/8672d72a-b3ca-448a-8696-6c213e6fb408).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
