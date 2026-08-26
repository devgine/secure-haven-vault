# Secure Haven Vault Helm chart

## Prerequisites

- Kubernetes 1.27+
- Helm 3
- A default StorageClass when the bundled PostgreSQL instance is enabled
- Access to `ghcr.io/devgine/secure-haven-vault` (an `imagePullSecret` if the package is private)

## Install with bundled PostgreSQL

Generate and preserve both values outside Git:

```bash
openssl rand -hex 32
openssl rand -base64 32
```

Then install:

```bash
helm upgrade --install secure-haven-vault ./helm/secure-haven-vault \
  --namespace secure-haven-vault \
  --create-namespace \
  --set-string config.masterEncryptionKey='<64-hex-key>' \
  --set-string postgresql.auth.password='<database-password>' \
  --set ingress.enabled=true \
  --set ingress.className=traefik \
  --set ingress.hosts[0].host=vault.example.com
```

The SQL schema is applied only when PostgreSQL initializes an empty data directory.

## Recommended: pre-created Kubernetes Secrets

For GitOps, do not commit secret values. Create secrets through your secret manager:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: secure-haven-app
type: Opaque
stringData:
  master-encryption-key: "<64-hex-key>"
  database-url: "postgres://vault:<password>@secure-haven-vault-postgresql:5432/vault"
---
apiVersion: v1
kind: Secret
metadata:
  name: secure-haven-postgresql
type: Opaque
stringData:
  postgres-password: "<password>"
```

Then configure:

```yaml
config:
  existingSecret: secure-haven-app
postgresql:
  auth:
    existingSecret: secure-haven-postgresql
```

## External PostgreSQL

```yaml
postgresql:
  enabled: false
config:
  existingSecret: secure-haven-app
```

The external secret must contain `database-url` and `master-encryption-key`. Apply
`db/init.sql` to the external database before starting the application.

## Validate

```bash
helm lint ./helm/secure-haven-vault \
  --set-string config.masterEncryptionKey=test \
  --set-string postgresql.auth.password=test
helm template secure-haven-vault ./helm/secure-haven-vault \
  --set-string config.masterEncryptionKey=test \
  --set-string postgresql.auth.password=test
```
