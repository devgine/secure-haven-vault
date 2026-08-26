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

{{- define "secure-haven-vault.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}{{ default (include "secure-haven-vault.fullname" .) .Values.serviceAccount.name }}{{- else }}{{ default "default" .Values.serviceAccount.name }}{{- end }}
{{- end }}

{{- define "secure-haven-vault.appSecretName" -}}
{{- default (printf "%s-app" (include "secure-haven-vault.fullname" .)) .Values.config.existingSecret }}
{{- end }}

{{- define "secure-haven-vault.postgresqlSecretName" -}}
{{- default (printf "%s-postgresql" (include "secure-haven-vault.fullname" .)) .Values.postgresql.auth.existingSecret }}
{{- end }}

{{- define "secure-haven-vault.postgresqlName" -}}
{{ printf "%s-postgresql" (include "secure-haven-vault.fullname" .) }}
{{- end }}
