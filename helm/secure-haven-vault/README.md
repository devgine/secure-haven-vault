# Secure Haven Vault Helm chart

The chart is published as an OCI artifact in GitHub Container Registry:

```text
oci://ghcr.io/devgine/charts/secure-haven-vault
```

It deploys the application (stateless, 2 replicas by default) and, unless an
external database is used, a PostgreSQL cluster managed by the
[CloudNativePG](https://cloudnative-pg.io) operator.

## Prerequisites

- Kubernetes 1.27+ and Helm 3.8+
- The **CloudNativePG operator** installed in the cluster (unless
  `postgresql.enabled=false`):

  ```bash
  helm repo add cnpg https://cloudnative-pg.github.io/charts
  helm upgrade --install cnpg cnpg/cloudnative-pg \
    --namespace cnpg-system --create-namespace
  ```

- A default StorageClass for the PostgreSQL volumes
- A CNI that enforces NetworkPolicies (or `networkPolicy.enabled=false`)
- Access to the application image `ghcr.io/devgine/secure-haven-vault`

## Secrets

In production, create the secrets yourself (External Secrets, Sealed Secrets,
…) and reference them; nothing sensitive goes through `--set` or Git.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: secure-haven-app
type: Opaque
stringData:
  master-encryption-key: "<openssl rand -hex 32>"
  admin-password: "<initial SUPER_ADMIN password, 12+ characters>"
---
apiVersion: v1
kind: Secret
metadata:
  name: secure-haven-postgresql
type: kubernetes.io/basic-auth
stringData:
  username: vault
  password: "<any strong password — no URL encoding needed>"
```

`values-production.yaml`:

```yaml
image:
  tag: "0.5.0"            # never "latest"; the schema rejects it

ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "24m"   # KeePass import batches
  hosts:
    - host: vault.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: vault-tls
      hosts: [vault.example.com]

config:
  existingSecret: secure-haven-app
  appUrl: https://vault.example.com
  admin:
    email: admin@example.com

postgresql:
  instances: 3
  auth:
    existingSecret: secure-haven-postgresql
  backup:
    retentionPolicy: 30d
    barmanObjectStore:
      destinationPath: s3://my-bucket/secure-haven-vault
      s3Credentials:
        accessKeyId: {name: backup-creds, key: ACCESS_KEY_ID}
        secretAccessKey: {name: backup-creds, key: SECRET_ACCESS_KEY}
  scheduledBackup:
    enabled: true

networkPolicy:
  appIngressFrom:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ingress-nginx
```

```bash
helm upgrade --install secure-haven-vault \
  oci://ghcr.io/devgine/charts/secure-haven-vault \
  --version 1.0.0 \
  --namespace secure-haven-vault --create-namespace \
  --values values-production.yaml
```

### Local / throwaway install

`--set` is acceptable for a local cluster only:

```bash
helm upgrade --install secure-haven-vault ./helm/secure-haven-vault \
  --namespace secure-haven-vault --create-namespace \
  --set-string config.masterEncryptionKey="$(openssl rand -hex 32)" \
  --set-string postgresql.auth.password="$(openssl rand -base64 32)" \
  --set config.admin.email=admin@example.com \
  --set-string config.admin.password='change-me-please-123' \
  --set replicaCount=1
```

## What the application does at startup

Each pod, before serving traffic (the readiness and startup probes wait for it):

1. applies pending **schema migrations** (embedded in the image, serialized
   across pods by a PostgreSQL advisory lock) — there is no `init.sql` to run,
   including on an external database;
2. creates the **SUPER_ADMIN** from `config.admin.email` and the
   `admin-password` key when the platform has none. No account becomes
   administrator by signing up;
3. grants the metrics role access to its single view;
4. re-wraps data keys after a master key rotation.

## Master key

Back up `master-encryption-key` separately: without it, stored secrets cannot
be decrypted.

**Rotation**: put the new key in `master-encryption-key` and the old one in
`master-encryption-key-previous`, then restart the deployment. The log line
`master_key_rewrap N` confirms the re-wrap; afterwards remove
`master-encryption-key-previous` and restart again.

## Metrics

`prometheus-postgres-exporter.enabled=true` deploys the exporter with a custom
`secret_expiry_days_remaining` gauge (labels: `secret_id`, `workspace_id` —
never a secret name). The chart then creates a dedicated PostgreSQL role
through CloudNativePG; it can read one view and nothing else.

```yaml
prometheus-postgres-exporter:
  enabled: true
postgresql:
  metricsRole:
    existingSecret: secure-haven-metrics   # basic-auth: username=exporter, password
```

The exporter's `config.datasource` defaults assume a release name containing
`secure-haven-vault`. With another release name, set
`config.datasource.host` to `<fullname>-postgresql-rw` and
`config.datasource.passwordSecret.name` to your metrics secret.

## External PostgreSQL

```yaml
postgresql:
  enabled: false
config:
  existingSecret: secure-haven-app   # must also contain `database-url`
```

The database user must own the schema (it runs the migrations). The trigram
search indexes are created when the `pg_trgm` extension is available and
skipped otherwise.

## Upgrading from 0.x

Version 1.0.0 replaces the single-pod PostgreSQL StatefulSet with a
CloudNativePG cluster. **Data is not migrated automatically**, and the secret
format changes.

1. Dump the old database while it is still running:

   ```bash
   kubectl -n secure-haven-vault exec secure-haven-vault-postgresql-0 -- \
     pg_dump -U vault -Fc vault > vault.dump
   ```

2. Create the new secrets (the PostgreSQL secret is now `kubernetes.io/basic-auth`
   with `username`/`password`; `database-url` is no longer needed), then upgrade
   with `--set replicaCount=0` so the application does not initialise an empty
   schema.
3. Restore into the new primary, then scale the application back up:

   ```bash
   kubectl -n secure-haven-vault exec -i secure-haven-vault-postgresql-1 -- \
     pg_restore -U postgres -d vault --no-owner --role=vault --clean --if-exists < vault.dump
   ```

4. Once verified, delete the old PVC `data-secure-haven-vault-postgresql-0`.

The former `exporter` role had a password committed in the repository
(`strong-password`) and read access to every table; the new one is created from
your secret and restricted to one view.

Other value changes: `image.tag` defaults to the chart `appVersion`,
`postgresql.persistence.*` became `postgresql.storage.*`, and
`postgresql.auth.passwordKey` is gone.

## Private GHCR packages

Public packages can be pulled without authentication. For a private chart,
create a GitHub personal access token with `read:packages`:

```bash
echo "$GHCR_TOKEN" | helm registry login ghcr.io \
  --username "$GHCR_USERNAME" --password-stdin
```

If the application image is private, create an image pull secret and reference
it:

```bash
kubectl create secret docker-registry ghcr-pull \
  --namespace secure-haven-vault \
  --docker-server=ghcr.io \
  --docker-username="$GHCR_USERNAME" \
  --docker-password="$GHCR_TOKEN"
```

```yaml
imagePullSecrets:
  - name: ghcr-pull
```

## Publishing a new chart version

Update `version` (and `appVersion` when the application is released) in
`Chart.yaml`, then push to `main`. The `Publish Helm chart` workflow builds the
dependencies from `Chart.lock`, lints, renders, packages and publishes the chart
under `oci://ghcr.io/devgine/charts/secure-haven-vault` using the repository's
automatic `GITHUB_TOKEN`.

The application image for a given `appVersion` is published by pushing the git
tag `v<appVersion>`.
