#!/bin/sh
# Run a command (QEMU) with the host side of the network tests alive: with-peer.sh <forward port> <command...>
port="$1"; shift
python3 "$(dirname "$0")/netpeer.py" "$port" > build-netpeer.log 2>&1 &
peer=$!
"$@"
rc=$?
kill $peer 2>/dev/null
wait $peer 2>/dev/null
exit $rc
