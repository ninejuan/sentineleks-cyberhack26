#!/usr/bin/env bash
# Crypto-mining (MITRE T1496) attack simulation for the SEKS demo. Safe by construction:
#   - /tmp/xmrig is a tiny shell script, not a miner. The kernel names a shebang script's process
#     after the script file, so Falco sees proc.name=xmrig -> "Crypto mining process detected".
#     (A renamed busybox binary would not work: busybox picks its applet from argv[0].)
#   - it opens TCP 3333 to the in-cluster stratum-sink only, never an external pool
#     -> Tetragon "detect-cryptominer-egress".
# Usage: scripts/simulate_cryptomining.sh [kube-context]
set -euo pipefail

CONTEXT="${1:-seks-demo}"
NS="demo"
KCTL=(kubectl --context "$CONTEXT" -n "$NS")

POD=$("${KCTL[@]}" get pod -l app=ledger-worker -o jsonpath='{.items[0].metadata.name}')
if [ -z "$POD" ]; then
  echo "ERROR: no ledger-worker pod in $NS. Run 'make demo-up' first." >&2
  exit 1
fi

echo "Attacking $NS/$POD"
"${KCTL[@]}" exec "$POD" -- sh -c '
  printf "%s\n" "#!/bin/sh" \
    "echo {\"method\":\"login\",\"params\":{\"agent\":\"xmrig/6.21\"}} | nc -w 3 stratum-sink.demo.svc.cluster.local 3333" \
    > /tmp/xmrig
  chmod +x /tmp/xmrig
  /tmp/xmrig
  echo "stratum connection exit code: $?"
'
echo "Done. Expect Falco + Tetragon events for $POD within ~30s, then a Slack approval card."
