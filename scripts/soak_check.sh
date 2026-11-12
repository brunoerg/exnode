#!/bin/bash
# Hourly soak health line (CSV) from RPC and the OS. Usage: soak_check.sh DATADIR [interval_s]
DATADIR=$1
INTERVAL=${2:-3600}
CSV=$DATADIR/soak_health.csv
COOKIE=$DATADIR/testnet4/.cookie
URL=http://127.0.0.1:48332/
[ -f "$CSV" ] || echo "time,uptime_s,tip,best_header,lag,peers,inbound,outbound,v2,rss_mib,errors,halted,rpc_ms" > "$CSV"
rpc() { curl -s -m 30 --user "$(cat "$COOKIE")" -H 'content-type: application/json' \
          -d "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"$1\",\"params\":[]}" "$URL"; }
while true; do
  sleep "$INTERVAL"
  t0=$(date +%s%N)
  info=$(rpc getblockchaininfo)
  t1=$(date +%s%N)
  peers=$(rpc getpeerinfo)
  up=$(rpc uptime | python3 -c 'import sys,json; print(json.load(sys.stdin)["result"])' 2>/dev/null || echo -1)
  read tip hdr <<<"$(echo "$info" | python3 -c 'import sys,json; r=json.load(sys.stdin)["result"]; print(r["blocks"], r["headers"])' 2>/dev/null || echo "-1 -1")"
  read n inb outb v2 <<<"$(echo "$peers" | python3 -c '
import sys,json
r=json.load(sys.stdin)["result"]
print(len(r), sum(p["inbound"] for p in r), sum(not p["inbound"] for p in r), sum(p["transport_protocol_type"]=="v2" for p in r))' 2>/dev/null || echo "-1 -1 -1 -1")"
  beam=$(ps -eo pid,args | grep "[b]eam.smp" | grep "datadir $DATADIR " | awk '{print $1}' | head -1)
  rss=$([ -n "$beam" ] && awk '/VmRSS/{print int($2/1024)}' /proc/$beam/status || echo -1)
  errors=$(grep -c "\[error\]" "$DATADIR/soak.log" 2>/dev/null || true)
  halted=$(grep -c "HALTED\|halted" "$DATADIR/soak.log" 2>/dev/null || true)
  echo "$(date -Is),$up,$tip,$hdr,$((hdr - tip)),$n,$inb,$outb,$v2,$rss,$errors,$halted,$(( (t1 - t0) / 1000000 ))" >> "$CSV"
done
