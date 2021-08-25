#!/bin/sh
set -eux
killall rrdsrv || true
find . -name '*.go' | entr -c -r sh -c '(go build || sleep 1) && ./rrdsrv'
