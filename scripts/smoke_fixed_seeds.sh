#!/bin/bash
# Smoke check for the fixed-seed bootstrap: a fresh testnet4 node
# with an empty address book and DNS pointed at a black-hole resolver
# (192.0.2.1, TEST-NET-1) must connect to peers from the fixed seeds within
# about two minutes. Usage: scripts/smoke_fixed_seeds.sh [seconds, default 150]
set -u
SECS=${1:-150}
REPO=$(cd "$(dirname "$0")/.." && pwd)
D=$(mktemp -d)
cat > "$D/inetrc" <<'RC'
{nameserver, {192,0,2,1}}.
{resolv_conf, ""}.
{hosts_file, ""}.
{lookup, [dns]}.
{timeout, 2000}.
RC
cd "$REPO" && eval "$(~/.local/bin/mise activate bash)"
ERL_INETRC="$D/inetrc" setsid mix exnode.node --chain testnet4 --datadir "$D/data" --norpc > "$D/log" 2>&1 &
end=$((SECONDS + SECS))
while [ $SECONDS -lt $end ]; do
  if grep -q "tip=.*peers=[1-9]" "$D/log" && grep -q "adding .* fixed seeds" "$D/log"; then break; fi
  sleep 5
done
grep -E "querying DNS seeds again|adding .* fixed seeds" "$D/log" | sed 's/^/  /'
grep "tip=" "$D/log" | tail -1 | sed 's/^/  /'
B=$(ps -eo pid,args | grep "[b]eam.smp" | grep "datadir $D/data" | awk '{print $1}')
[ -n "$B" ] && kill -TERM $B
if grep -q "tip=.*peers=[1-9]" "$D/log" && grep -q "adding .* fixed seeds" "$D/log"; then
  echo "OK: connected via fixed seeds"; rm -rf "$D"; exit 0
else
  echo "FAILED: see $D/log"; exit 1
fi
