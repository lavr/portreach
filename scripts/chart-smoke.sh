#!/usr/bin/env bash
#
# chart-smoke.sh — local smoke test for the portreach Helm chart.
#
# Spins up a kind cluster whose DNS domain is NOT cluster.local (corp.test) with
# two worker nodes, then A/B-tests agent discovery through the UI:
#   A) discovery.mode=fqdn + clusterDomain=cluster.local  -> NXDOMAIN, zero agents
#      (reproduces the bug the chart 0.1.1 change fixes)
#   B) discovery.mode=relative (the new default)          -> resolves via the Go
#      resolver's search domains, /api/check returns per-node results
#
# Requires: docker (OrbStack), kind, kubectl, helm, curl.
# Run from the repo root:  ./scripts/chart-smoke.sh
#
# Env overrides:
#   CLUSTER  kind cluster name        (default portreach-smoke)
#   NS       namespace                (default portreach)
#   IMAGE    image ref                (default lavr/portreach:0.1.0)
#   CHART    chart path               (default charts/portreach)
#   KEEP     1 = keep cluster on exit (default 0, teardown)
set -euo pipefail

CLUSTER="${CLUSTER:-portreach-smoke}"
NS="${NS:-portreach}"
IMAGE="${IMAGE:-lavr/portreach:0.1.0}"
CHART="${CHART:-charts/portreach}"
KEEP="${KEEP:-0}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KIND_CFG="$ROOT/scripts/kind-portreach.yaml"
PF_PID=""

log()  { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 1; }; }
need docker; need kind; need kubectl; need helm; need curl

cleanup() {
  [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null || true
  if [ "$KEEP" = "1" ]; then
    log "KEEP=1 — leaving cluster '$CLUSTER' (delete: kind delete cluster --name $CLUSTER)"
  else
    log "tearing down kind cluster '$CLUSTER'"
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

log "create kind cluster '$CLUSTER' (dnsDomain from $KIND_CFG)"
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER" --config "$KIND_CFG"
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null

log "pull + load image $IMAGE into the cluster"
docker pull "$IMAGE"
kind load docker-image "$IMAGE" --name "$CLUSTER"

# deploy <mode> [extra helm --set args...]
deploy() {
  local mode="$1"; shift
  log "helm upgrade --install portreach (discovery.mode=$mode $*)"
  helm upgrade --install portreach "$ROOT/$CHART" \
    -n "$NS" --create-namespace \
    --set image.tag="${IMAGE##*:}" \
    --set image.pullPolicy=IfNotPresent \
    --set ui.discovery.mode="$mode" \
    "$@" \
    --wait --timeout 150s
  kubectl -n "$NS" rollout status \
    "$(kubectl -n "$NS" get deploy -l app.kubernetes.io/component=ui -o name)" --timeout=120s
  # give the DaemonSet a moment to schedule on both workers
  kubectl -n "$NS" rollout status \
    "$(kubectl -n "$NS" get ds -l app.kubernetes.io/component=agent -o name)" --timeout=120s
  echo "agents scheduled: $(kubectl -n "$NS" get pods -l app.kubernetes.io/component=agent --no-headers | wc -l | tr -d ' ')"
}

# check <label>  — port-forward the UI and hit /api/check
check() {
  local label="$1"
  local ui_pod
  ui_pod="$(kubectl -n "$NS" get pod -l app.kubernetes.io/component=ui -o jsonpath='{.items[0].metadata.name}')"
  kubectl -n "$NS" port-forward "pod/$ui_pod" 18080:8080 >/dev/null 2>&1 &
  PF_PID=$!
  sleep 3
  log "[$label] GET /api/check?host=github.com&port=443"
  curl -fsS "http://localhost:18080/api/check?host=github.com&port=443" \
    || echo "(request failed / non-2xx — expected for case A)"
  echo
  kill "$PF_PID" 2>/dev/null || true; PF_PID=""
}

# A) reproduce the bug: fqdn name <svc>.<ns>.svc.cluster.local on a corp.test cluster
deploy fqdn --set clusterDomain=cluster.local
check "A: fqdn + cluster.local on corp.test (expect zero agents / error)"

# B) the fix: relative <svc>.<ns>.svc resolves via the pod search domain
deploy relative
check "B: relative default (expect per-node TCP results from 2 agents)"

log "smoke complete. Re-run with KEEP=1 to keep the cluster for inspection."
