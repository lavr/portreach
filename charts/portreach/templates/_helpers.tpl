{{/*
Expand the chart name.
*/}}
{{- define "portreach.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a release-qualified base name.
*/}}
{{- define "portreach.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "portreach.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "portreach.labels" -}}
helm.sh/chart: {{ include "portreach.chart" . }}
app.kubernetes.io/name: {{ include "portreach.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/part-of: {{ include "portreach.name" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end -}}

{{- define "portreach.annotations" -}}
{{- with .Values.commonAnnotations }}
{{- toYaml . }}
{{- end }}
{{- end -}}

{{- define "portreach.ui.fullname" -}}
{{- printf "%s-ui" (include "portreach.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "portreach.agent.fullname" -}}
{{- printf "%s-agent" (include "portreach.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "portreach.ui.selectorLabels" -}}
app.kubernetes.io/name: {{ include "portreach.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: ui
{{- end -}}

{{- define "portreach.agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "portreach.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: agent
{{- end -}}

{{- define "portreach.ui.labels" -}}
{{ include "portreach.labels" . }}
app.kubernetes.io/component: ui
{{- end -}}

{{- define "portreach.agent.labels" -}}
{{ include "portreach.labels" . }}
app.kubernetes.io/component: agent
{{- end -}}

{{- define "portreach.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}

{{- define "portreach.ui.serviceAccountName" -}}
{{- if .Values.serviceAccounts.ui.create -}}
{{- default (include "portreach.ui.fullname" .) .Values.serviceAccounts.ui.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccounts.ui.name -}}
{{- end -}}
{{- end -}}

{{- define "portreach.agent.serviceAccountName" -}}
{{- if .Values.serviceAccounts.agent.create -}}
{{- default (include "portreach.agent.fullname" .) .Values.serviceAccounts.agent.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccounts.agent.name -}}
{{- end -}}
{{- end -}}

{{- define "portreach.agent.dnsName" -}}
{{- $discovery := .Values.ui.agentDiscovery | default dict -}}
{{- with $discovery.dnsName -}}
{{- . -}}
{{- else -}}
{{- $svc := include "portreach.agent.fullname" . -}}
{{- $mode := $discovery.mode | default "relative" -}}
{{- if eq $mode "relative" -}}
{{- printf "%s.%s.svc" $svc .Release.Namespace -}}
{{- else if eq $mode "fqdn" -}}
{{- printf "%s.%s.svc.%s" $svc .Release.Namespace .Values.clusterDomain -}}
{{- else if eq $mode "bare" -}}
{{- $svc -}}
{{- else -}}
{{- fail (printf "ui.agentDiscovery.mode must be relative, fqdn or bare (got %q)" $mode) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "portreach.auth.secretName" -}}
{{- .Values.ui.auth.existingSecret | default (printf "%s-auth" (include "portreach.ui.fullname" .)) -}}
{{- end -}}

{{- define "portreach.auth.providerSecretEnv" -}}
{{- $p := .provider -}}
{{- $id := required "ui.auth.providers[].id is required" $p.id -}}
{{- default (printf "PORTREACH_AUTH_%s_CLIENT_SECRET" (regexReplaceAll "[^A-Za-z0-9_]" (upper $id) "_")) $p.clientSecretEnv -}}
{{- end -}}

{{- define "portreach.auth.providerSecretKey" -}}
{{- $p := .provider -}}
{{- $id := required "ui.auth.providers[].id is required" $p.id -}}
{{- default (printf "%sClientSecret" (regexReplaceAll "[^A-Za-z0-9._-]" $id "-")) $p.clientSecretKey -}}
{{- end -}}

{{/*
Auth toggles. Browser SSO and the API bearer path are independent. The legacy
`ui.auth.enabled` is honoured as a browser toggle for back-compat. Each helper
emits the string "true" (truthy) or "" (falsy) so callers can `eq "true"`.
*/}}
{{- define "portreach.auth.browser.enabled" -}}
{{- $auth := .Values.ui.auth | default dict -}}
{{- $browser := $auth.browser | default dict -}}
{{- if or $browser.enabled $auth.enabled -}}true{{- end -}}
{{- end -}}

{{- define "portreach.auth.api.enabled" -}}
{{- $api := (.Values.ui.auth | default dict).api | default dict -}}
{{- if $api.enabled -}}true{{- end -}}
{{- end -}}

{{- define "portreach.auth.enabled" -}}
{{- if or (eq (include "portreach.auth.browser.enabled" .) "true") (eq (include "portreach.auth.api.enabled" .) "true") -}}true{{- end -}}
{{- end -}}

{{/*
Agent shared-token helpers. The token is configured when a literal value or an
existing Secret is supplied; the chart manages the Secret only for a literal.
*/}}
{{- define "portreach.agent.token.enabled" -}}
{{- $a := .Values.agent.auth | default dict -}}
{{- if or $a.token $a.existingSecret -}}true{{- end -}}
{{- end -}}

{{- define "portreach.agent.token.secretName" -}}
{{- $a := .Values.agent.auth | default dict -}}
{{- $a.existingSecret | default (printf "%s-token" (include "portreach.agent.fullname" .)) -}}
{{- end -}}

{{/*
Checksum of the chart-managed agent token so a value change rolls the pods that
mount it. Empty for an externally-managed Secret (rotation = manual rollout).
*/}}
{{- define "portreach.agent.token.checksum" -}}
{{- $a := .Values.agent.auth | default dict -}}
{{- if and $a.token (not $a.existingSecret) -}}
{{- $a.token | toString | sha256sum -}}
{{- end -}}
{{- end -}}

{{- define "portreach.probe" -}}
{{- $probe := . -}}
{{- if and $probe $probe.enabled -}}
{{- omit $probe "enabled" | toYaml -}}
{{- end -}}
{{- end -}}
