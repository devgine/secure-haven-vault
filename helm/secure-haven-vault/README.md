# Secure Haven Vault Helm chart

The chart is published as an OCI artifact in GitHub Container Registry:

```text
oci://ghcr.io/devgine/charts/secure-haven-vault
```

## Prerequisites

- Kubernetes 1.27+
- Helm 3.8+
- A default StorageClass when the bundled PostgreSQL instance is enabled
- Access to the application image `ghcr.io/devgine/secure-haven-vault`
- Access to the chart package if it is private

## Install directly from GHCR

Generate the encryption key and database password, then store them securely:

```bash
MASTER_ENCRYPTION_KEY="$(openssl rand -hex 32)"
POSTGRES_PASSWORD="$(openssl rand -base64 32)"
```

Install version `0.1.0` directly from GHCR:

```bash
helm upgrade --install secure-haven-vault \
  oci://ghcr.io/devgine/charts/secure-haven-vault \
  --version 0.1.0 \
  --namespace secure-haven-vault \
  --create-namespace \
  --set-string config.masterEncryptionKey="$MASTER_ENCRYPTION_KEY" \
  --set-string postgresql.auth.password="$POSTGRES_PASSWORD" \
  --set ingress.enabled=true \
  --set ingress.className=traefik \
  --set ingress.hosts[0].host=vault.example.com
```

The SQL schema is applied only when PostgreSQL initializes an empty data directory.
Back up `MASTER_ENCRYPTION_KEY` separately: losing it makes stored secrets
undecryptable.

### Private GHCR packages

Public packages can be pulled without authentication. For a private chart, create
a GitHub personal access token with `read:packages`, then authenticate Helm:

```bash
export GHCR_USERNAME="<github-username>"
export GHCR_TOKEN="<github-token>"

echo "$GHCR_TOKEN" | helm registry login ghcr.io \
  --username "$GHCR_USERNAME" \
  --password-stdin
```

If the application image is private, create an image pull secret:

```bash
kubectl create secret docker-registry ghcr-pull \
  --namespace secure-haven-vault \
  --docker-server=ghcr.io \
  --docker-username="$GHCR_USERNAME" \
  --docker-password="$GHCR_TOKEN"
```

Then add it to your values:

```yaml
imagePullSecrets:
  - name: ghcr-pull
```

## Recommended: pre-created Kubernetes Secrets

For GitOps, do not commit secret values. Create secrets through your secret
manager:

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

Reference them from a `values-production.yaml` file:

```yaml
config:
  existingSecret: secure-haven-app
postgresql:
  auth:
    existingSecret: secure-haven-postgresql
```

Then deploy:

```bash
helm upgrade --install secure-haven-vault \
  oci://ghcr.io/devgine/charts/secure-haven-vault \
  --version 0.1.0 \
  --namespace secure-haven-vault \
  --create-namespace \
  --values values-production.yaml
```

## External PostgreSQL

Use a pre-created secret containing `database-url` and
`master-encryption-key`:

```yaml
postgresql:
  enabled: false
config:
  existingSecret: secure-haven-app
```

Apply `db/init.sql` to the external database before starting the application.

## Publishing a new chart version

Update `version` in `Chart.yaml`, then push the change to `main`. The
`Publish Helm chart` workflow:

1. runs `helm lint`;
2. renders the manifests;
3. packages the chart;
4. authenticates to GHCR with the repository's automatic `GITHUB_TOKEN`;
5. publishes it under `oci://ghcr.io/devgine/charts/secure-haven-vault`.

No additional Actions secret is required. The workflow needs the repository
permission `packages: write`, which is declared in the workflow.
