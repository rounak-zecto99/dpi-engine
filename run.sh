#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
if [ ! -f target/dpi-engine-java.jar ]; then ./build.sh; fi
java -jar target/dpi-engine-java.jar "$@"
