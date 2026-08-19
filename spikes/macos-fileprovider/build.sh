#!/bin/zsh
# Build, sign and register the Phase 0c / OQ-D File Provider spike.
#
# Run ON A MAC. Ad-hoc signing only — no Apple certificate, no provisioning
# profile, no notarization, and deliberately no developer identity of any kind.
# That is the finding, not a limitation: registration needs none of them.
#
# ---------------------------------------------------------------------------
# THE THREE THINGS THAT MATTER, and why each was expensive
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
#
# 3. `com.apple.security.application-groups`
#
#    Must list exactly the string Info-appex.plist gives for
#    NSExtensionFileProviderDocumentGroup. Without it the bundle signs clean,
#    `pluginkit` lists the extension, and `fileproviderd` silently discards it:
#    "doesn't have a group container for document group ... Ignoring the
#    extension." The caller sees -2014, which reads as "never discovered".
#    This is what the first reconstruction of this spike was missing.
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
# TWO REGISTRATION RULES, both measured rather than guessed. See FINDINGS.md.
#
#   a. `lsregister -f` alone is NOT enough. It registers the containing APP with
#      Launch Services and leaves the .appex absent from `pluginkit` entirely,
#      confirmed unchanged after a 45 s wait — so this is not indexing lag. The
#      plug-in must be handed to pkd with `pluginkit -a`.
#
#   b. `pluginkit -a` MUST FOLLOW `lsregister -f` IMMEDIATELY. Do not put a sleep
#      between these two lines. This looked like superstition, so it was measured:
#      six alternating trials on the host, identical bundles, varying only this
#      gap, with the document group asserted to match the entitlement each time.
#
#          gap = 0 s  ->  ACCEPTED, ACCEPTED, ACCEPTED
#          gap = 5 s  ->  REFUSED -2014, REFUSED -2014, REFUSED -2014
#
#      Perfect separation, 6/6. With the gap, `fileproviderd` never logs the
#      request at all — the failure is upstream of it, and silent. An earlier
#      version of this script slept 5 s here and failed three times in a row while
#      the identical bundle succeeded by hand.
"$LSR" -f "$APP"
pluginkit -a "$APPEX"
sleep 8
pluginkit -mAvvv >/dev/null 2>&1

echo "=== discovered by pluginkit? ==="
PK=$(pluginkit -mAvvv 2>/dev/null | grep -i -A3 "shepherd\.spike" || true)
if [ -n "$PK" ]; then
    echo "$PK" | sed 's/^/  /'
else
    echo "  NOT LISTED — check the sandbox entitlement"
fi
pluginkit -e use -i kr.swjeon.shepherd.spike.provider 2>&1 | sed 's/^/  elected: /'
sleep 3

echo "=== domain registration ==="
"$APP/Contents/MacOS/ShepherdSpike" 2>&1 | sed 's/^/  /'

# `fileproviderctl dump` hangs indefinitely on some hosts — observed wedged for
# 12+ minutes with no output, taking the whole script with it. It is diagnostic
# only, so bound it rather than let it own the run.
echo "=== domain state (authoritative; -2011 = user-disabled) ==="
( sleep 20; pkill -f "fileproviderctl dump" 2>/dev/null ) &
WATCHDOG=$!
fileproviderctl dump 2>/dev/null | grep -A4 -i shepherd | head -12 | sed 's/^/  /' || echo "  (fileproviderctl reported nothing)"
kill "$WATCHDOG" 2>/dev/null || true

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
    pluginkit -r "$APPEX" 2>/dev/null || true
    "$LSR" -u "$APP" 2>/dev/null || true
    rm -rf "$APP" "$BUILD"
    # The group container and the sandbox container outlive the bundle.
    rm -rf ~/Library/Containers/kr.swjeon.shepherd.spike* 2>/dev/null || true
    rm -rf ~/Library/Group\ Containers/group.kr.swjeon.shepherd.spike 2>/dev/null || true
    echo "  removed $APP"
fi
