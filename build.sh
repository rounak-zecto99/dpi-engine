#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
rm -rf target/classes
mkdir -p target/classes
find src/main/java -name '*.java' -print > target/sources.txt
javac --release 17 -d target/classes @target/sources.txt
jar --create --file target/dpi-engine-java.jar --main-class Main -C target/classes .
echo "Build successful: target/dpi-engine-java.jar"
