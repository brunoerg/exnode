#!/bin/bash
# Testnet4 soak. Starts exnode detached (survives the
# shell) with every feature on, plus an hourly health check.
#   scripts/soak.sh start [DATADIR]   (default ~/exnode-testnet4)
#   scripts/soak.sh stop  [DATADIR]
#   scripts/soak.sh status [DATADIR]
set -euo pipefail
cmd=${1:-status}
DATADIR=${2:-$HOME/exnode-testnet4}
REPO=$(cd "$(dirname "$0")/.." && pwd)
LOG=$DATADIR/soak.log
PIDF=$DATADIR/soak.pid
CHECKPIDF=$DATADIR/soak_check.pid

case $cmd in
start)
  if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then echo "already running: $(cat "$PIDF")"; exit 1; fi
  cd "$REPO"
  eval "$(~/.local/bin/mise activate bash)"
  MIX_ENV=dev mix compile >/dev/null
  { echo "=== soak start $(date -Is) commit $(git rev-parse --short HEAD) ==="; } >> "$LOG"
  setsid nohup mix exnode.node --chain testnet4 --datadir "$DATADIR" --listen 48333 \
      --blockfilterindex --peerblockfilters --indexscripthash --restport 3002 \
      --status-file "$DATADIR/status.json" >> "$LOG" 2>&1 < /dev/null &
  echo $! > "$PIDF"
  setsid nohup "$REPO/scripts/soak_check.sh" "$DATADIR" >> "$DATADIR/soak_check.log" 2>&1 < /dev/null &
  echo $! > "$CHECKPIDF"
  echo "started node $(cat "$PIDF"), health check $(cat "$CHECKPIDF"); log $LOG"
  ;;
stop)
  for f in "$CHECKPIDF" "$PIDF"; do
    if [ -f "$f" ]; then
      p=$(cat "$f")
      # The mix wrapper's process group holds the BEAM: signal the group (SIGTERM: Core-like clean shutdown).
      kill -TERM -- -"$p" 2>/dev/null || kill -TERM "$p" 2>/dev/null || true
      rm -f "$f"
    fi
  done
  echo "=== soak stop $(date -Is) ===" >> "$LOG"
  echo stopped
  ;;
status)
  [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null && echo "node running: $(cat "$PIDF")" || echo "node not running"
  [ -f "$DATADIR/soak_health.csv" ] && { head -1 "$DATADIR/soak_health.csv"; tail -3 "$DATADIR/soak_health.csv"; }
  ;;
esac
