#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
export CGO_ENABLED=0
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT
dest="${1:-$PWD/dist}"
mkdir -p "$dest"
dest="$(cd "$dest" && pwd)"
app="$build/NBT Evo Trio Collector.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o "$build/darwin-arm64" .
GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o "$build/darwin-amd64" .
lipo -create "$build/darwin-arm64" "$build/darwin-amd64" -output "$app/Contents/MacOS/NBTEvoTrioCollector"
cp Info.plist "$app/Contents/Info.plist"
cp -R third-party "$app/Contents/Resources/"
cp 'Quick Start.md' "$app/Contents/Resources/"
codesign --force --sign - "$app"
codesign --verify --strict "$app"
ditto -c -k --keepParent "$app" "$dest/NBT-Evo-Trio-Collector-macOS.zip"
stage="$build/windows-x64"
mkdir -p "$stage"
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w -H windowsgui' -o "$stage/NBT Evo Trio Collector.exe" .
cp 'Quick Start.md' "$stage/"
cp -R third-party "$stage/"
ditto -c -k "$stage" "$dest/NBT-Evo-Trio-Collector-Windows-x64.zip"
(cd "$dest" && shasum -a 256 NBT-Evo-Trio-Collector-*.zip > SHA256SUMS.txt)
