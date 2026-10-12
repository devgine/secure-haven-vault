{{- define "secure-haven-vault.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "secure-haven-vault.fullname" -}}
{{- if .Values.fullnameOverride }}{{ .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}{{ .Release.Name | trunc 63 | trimSuffix "-" }}{{- else }}{{ printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}{{- end }}
{{- end }}
{{- end }}

{{- define "secure-haven-vault.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "secure-haven-vault.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "secure-haven-vault.selectorLabels" -}}
app.kubernetes.io/name: {{ include "secure-haven-vault.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Image : digest immuable s'il est fourni, sinon tag (défaut : appVersion). */}}
{{- define "secure-haven-vault.image" -}}
{{- if .Values.image.digest }}{{ printf "%s@%s" .Values.image.repository .Values.image.digest }}{{- else }}{{ printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}{{- end }}
{{- end }}

{{- define "secure-haven-vault.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}{{ default (include "secure-haven-vault.fullname" .) .Values.serviceAccount.name }}{{- else }}{{ default "default" .Values.serviceAccount.name }}{{- end }}
{{- end }}

{{- define "secure-haven-vault.appSecretName" -}}
{{- default (printf "%s-app" (include "secure-haven-vault.fullname" .)) .Values.config.existingSecret }}
{{- end }}

{{/* Nom du Cluster CloudNativePG ; le service d'écriture est <nom>-rw. */}}
{{- define "secure-haven-vault.postgresqlName" -}}
{{ printf "%s-postgresql" (include "secure-haven-vault.fullname" .) }}
{{- end }}

{{- define "secure-haven-vault.postgresqlSecretName" -}}
{{- default (printf "%s-postgresql" (include "secure-haven-vault.fullname" .)) .Values.postgresql.auth.existingSecret }}
{{- end }}

{{- define "secure-haven-vault.metricsSecretName" -}}
{{- default (printf "%s-metrics" (include "secure-haven-vault.fullname" .)) .Values.postgresql.metricsRole.existingSecret }}
{{- end }}

{{- define "secure-haven-vault.metricsEnabled" -}}
{{- if (index .Values "prometheus-postgres-exporter").enabled }}true{{- end }}
{{- end }}

{{/* URL publique : valeur explicite, sinon https://<premier hôte de l'ingress>. */}}
{{- define "secure-haven-vault.appUrl" -}}
{{- if .Values.config.appUrl }}{{ .Values.config.appUrl }}{{- else if and .Values.ingress.enabled .Values.ingress.hosts }}{{ printf "https://%s" (index .Values.ingress.hosts 0).host }}{{- end }}
{{- end }}
