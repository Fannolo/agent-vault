#!/bin/sh
# Builds the private human app as an ad hoc signed bundle under .build/app. Development only:
# it installs nothing, touches no system settings, and an ad hoc signature cannot create the
# protected approval key (see docs/NATIVE-APP.md).
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
config=${1:-release}
case "$config" in debug|release) ;; *) echo "usage: $0 [debug|release]" >&2; exit 64;; esac
cd "$root"
swift build -c "$config" --product AgentVaultApp
binary=$(swift build -c "$config" --product AgentVaultApp --show-bin-path)/AgentVaultApp
bundle="$root/.build/app/AgentVault.app"
rm -rf "$bundle"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
cp "$binary" "$bundle/Contents/MacOS/AgentVault"
cp "$root/packaging/mac/Info.plist" "$bundle/Contents/Info.plist"
plutil -lint "$bundle/Contents/Info.plist" >/dev/null
codesign --force --sign - --options runtime --identifier dev.agentvault.app "$bundle"
codesign --verify --strict --verbose=2 "$bundle"
echo "$bundle"
