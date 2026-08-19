#!/bin/zsh
# Build, sign and register the Phase 0c / OQ-D File Provider spike.
#
# Run ON A MAC. Ad-hoc signing only — no Apple certificate, no provisioning
# profile, no notarization, and deliberately no developer identity of any kind.
# That is the finding, not a limitation: registration needs none of them.
#
# ---------------------------------------------------------------------------
# THE TWO LINES THAT MATTER, and why each was expensive
#
# 1. `-emit-executable ... -Xlinker -e -Xlinker _NSExtensionMain`
#
#    An app extension binary is Mach-O MH_EXECUTE whose entry point is
#    NSExtensionMain. Built the obvious way — `-emit-library -Xlinker -bundle`
#    — you get MH_BUNDLE, and **codesign SILENTLY IGNORES --entitlements on a
#    bundle-type Mach-O**: exit 0, no warning, nothing embedded. Every
#    downstream symptom (no entitlements, extension never discovered, -2014)
#    follows from that one flag, and it cost nine probes because the failures
#    all looked like signing problems. Verify with:
#        file .../Provider   # must say "Mach-O 64-bit executable", NOT "bundle"
#
# 2. `com.apple.security.app-sandbox`
#
#    Without it `pkd` refuses the plug-in outright — "plug-ins must be
#    sandboxed" — and it never appears in `pluginkit` at all. It is an
#    UNRESTRICTED entitlement, so ad-hoc can self-grant it. Contrast
#    `com.apple.developer.fileprovider.testing-mode`, which is restricted:
#    signing that ad-hoc gets the process AMFI-SIGKILLed (exit 137,
#    "adhoc signed but contains restricted entitlements").
# ---------------------------------------------------------------------------
set -eu
HERE=${0:a:h}
APP=${1:-/Applications/ShepherdSpike.app}
APPEX="$APP/Contents/PlugIns/Provider.appex"
BUILD=$(mktemp -d)

echo "=== macOS $(sw_vers -productVersion), signing identities present: $(security find-identity -v -p codesigning 2>/dev/null | tail -1)"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APPEX/Contents/MacOS"

# --- 1. the appex: MH_EXECUTE with NSExtensionMain as entry point ----------
swiftc -emit-executable -o "$BUILD/Provider" "$HERE/Provider.swift" \
    -framework Foundation -framework FileProvider \
    -Xlinker -e -Xlinker _NSExtensionMain
swiftc -emit-executable -o "$BUILD/ShepherdSpike" "$HERE/Host.swift" \
    -framework Foundation -framework FileProvider

echo "=== appex Mach-O type (MUST be 'executable', not 'bundle') ==="
file "$BUILD/Provider" | sed 's/^/  /'
case "$(file -b "$BUILD/Provider")" in
    *bundle*) echo "  FATAL: built MH_BUNDLE — entitlements would be silently discarded"; exit 1 ;;
esac

cp "$BUILD/Provider" "$APPEX/Contents/MacOS/Provider"
cp "$BUILD/ShepherdSpike" "$APP/Contents/MacOS/ShepherdSpike"
cp "$HERE/Info-app.plist"   "$APP/Contents/Info.plist"
cp "$HERE/Info-appex.plist" "$APPEX/Contents/Info.plist"

# --- 2. sign ad-hoc WITH the sandbox entitlement ---------------------------
codesign --force --sign - --entitlements "$HERE/Provider.entitlements" "$APPEX"
codesign --force --sign - --entitlements "$HERE/Provider.entitlements" "$APP"

echo "=== entitlements actually embedded? (0 means the MH_BUNDLE bug) ==="
codesign -d --entitlements - "$APPEX" 2>/dev/null | grep -c "app-sandbox" | sed 's/^/  app-sandbox entries: /'
codesign -dvvv "$APPEX" 2>&1 | grep -E "^flags|^Signature" | sed 's/^/  /'

# --- 3. register and probe -------------------------------------------------
LSR=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
"$LSR" -f "$APP"
sleep 5

echo "=== discovered by pluginkit? ==="
pluginkit -m -p com.apple.fileprovider-nonui 2>/dev/null | grep -i shepherd | sed 's/^/  /' || echo "  NOT LISTED — check the sandbox entitlement"

echo "=== domain registration ==="
"$APP/Contents/MacOS/ShepherdSpike" 2>&1 | sed 's/^/  /'

echo "=== domain state (authoritative; -2011 = user-disabled) ==="
fileproviderctl dump 2>/dev/null | grep -A4 -i shepherd | head -12 | sed 's/^/  /' || echo "  (fileproviderctl reported nothing)"

# Set KEEP=1 to leave the bundle installed for diagnosis — `pluginkit -mAvvv`,
# `log show --predicate 'process == "pkd"'` and `fileproviderctl dump` all need
# it still on disk. Default is to remove it: a spike that leaves a registered
# provider behind puts a mount in the user's sidebar.
if [ "${KEEP:-0}" = "1" ]; then
    echo "=== KEEP=1: leaving $APP installed ==="
    echo "  remove with: '$LSR' -u '$APP'; rm -rf '$APP'"
    rm -rf "$BUILD"
else
    echo "=== teardown ==="
    "$LSR" -u "$APP" 2>/dev/null || true
    rm -rf "$APP" "$BUILD"
    echo "  removed $APP"
fi
