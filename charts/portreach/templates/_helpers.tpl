{{/*
Expand the name of the chart.
*/}}
{{- define "portreach.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "portreach.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "portreach.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "portreach.labels" -}}
helm.sh/chart: {{ include "portreach.chart" . }}
app.kubernetes.io/part-of: {{ include "portreach.name" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
UI component selector labels.
*/}}
{{- define "portreach.ui.selectorLabels" -}}
app.kubernetes.io/name: {{ include "portreach.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: ui
{{- end }}

{{/*
Agent component selector labels.
*/}}
{{- define "portreach.agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "portreach.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: agent
{{- end }}

{{/*
UI resource name.
*/}}
{{- define "portreach.ui.fullname" -}}
{{- printf "%s-ui" (include "portreach.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Agent resource name.
*/}}
{{- define "portreach.agent.fullname" -}}
{{- printf "%s-agent" (include "portreach.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Headless agent service DNS name, used by the UI for agent discovery.
Priority chain (portable by default):
  1. ui.agentsDnsName  — raw override, used verbatim (escape hatch).
  2. ui.discovery.mode — how the default name is built (default "relative"):
       relative -> <svc>.<ns>.svc            (resolved via pod search domain)
       fqdn     -> <svc>.<ns>.svc.<domain>   (uses clusterDomain)
       bare     -> <svc>                      (in-namespace only)
*/}}
{{- define "portreach.agent.dnsName" -}}
{{- $svc := include "portreach.agent.fullname" . -}}
{{- with .Values.ui.agentsDnsName -}}
{{- . -}}
{{- else -}}
{{- $mode := (.Values.ui.discovery | default dict).mode | default "relative" -}}
{{- if eq $mode "fqdn" -}}
{{- printf "%s.%s.svc.%s" $svc .Release.Namespace .Values.clusterDomain -}}
{{- else if eq $mode "bare" -}}
{{- $svc -}}
{{- else if eq $mode "relative" -}}
{{- printf "%s.%s.svc" $svc .Release.Namespace -}}
{{- else -}}
{{- fail (printf "ui.discovery.mode must be relative, fqdn or bare (got %q)" $mode) -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
The image reference. image.tag is the single source of truth:
  set   -> used verbatim (0.1.0, 0.1.0-rootless, sha-abc123, latest, ...);
  empty -> defaults to .Chart.AppVersion (plain, no -rootless suffix).
Shared by the UI Deployment and agent DaemonSet so they never drift.
*/}}
{{- define "portreach.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "portreach.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "portreach.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
