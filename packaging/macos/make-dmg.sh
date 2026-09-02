#!/usr/bin/env bash
#
# Builds the macOS application bundle and the disk image around it.
#
#   packaging/macos/make-dmg.sh 2.0.0
#   packaging/macos/make-dmg.sh 2.0.0 target/aarch64-apple-darwin/release apple-silicon
#
# The second argument is where the two binaries are, the third is what to call
# the result. Both exist because the release builds one image per architecture
# rather than one universal image: two downloads of five megabytes each, rather
# than one of ten that is half dead weight on every machine.
#
# Runs on macOS only: iconutil and hdiutil are the two pieces with no useful
# substitute elsewhere.
#
# The disk image is the familiar one, with the application on the left and a
# link to Applications on the right, so it is dragged across rather than
# explained.

set -euo pipefail

version=${1:?give me a version}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
binaries=${2:-$root/target/release}
label=${3:-}

name="Home Connect Profile Downloader"
app="$root/dist/$name.app"
dmg="$root/dist/hcpd-$version-macos${label:+-$label}.dmg"
staging="$root/dist/dmg"

rm -rf "$app" "$staging" "$dmg"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" "$staging"

# Both binaries, side by side. The application looks for the helper next to
# itself, which inside a bundle means Contents/MacOS.
cp "$binaries/hcpd" "$app/Contents/MacOS/hcpd"
cp "$binaries/hcpd-login" "$app/Contents/MacOS/hcpd-login"
chmod +x "$app/Contents/MacOS/hcpd" "$app/Contents/MacOS/hcpd-login"

# Said out loud, because a disk image that runs on only half the Macs is the
# sort of thing nobody notices until somebody with the other half complains.
echo "architectures: $(lipo -archs "$app/Contents/MacOS/hcpd")"

iconutil -c icns "$here/../icon/rendered/hcpd.iconset" -o "$app/Contents/Resources/hcpd.icns"

# CFBundleName is what the menu bar says. Without it macOS uses the executable
# name and the menu reads "hcpd".
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>$name</string>
  <key>CFBundleDisplayName</key><string>$name</string>
  <key>CFBundleExecutable</key><string>hcpd</string>
  <key>CFBundleIdentifier</key><string>com.github.bruestel.hcpd</string>
  <key>CFBundleIconFile</key><string>hcpd</string>
  <key>CFBundleShortVersionString</key><string>$version</string>
  <key>CFBundleVersion</key><string>$version</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

# Signed with nothing, which is what "-" means. It is not a certificate and it
# does not get past Gatekeeper; it only stops macOS from refusing an unsigned
# bundle outright on arm64, where an ad-hoc signature is required to run at all.
codesign --force --deep --sign - "$app"

cp -R "$app" "$staging/"
ln -s /Applications "$staging/Applications"

hdiutil create -volname "$name" -srcfolder "$staging" -ov -format UDZO "$dmg"
rm -rf "$staging"

echo "written: $dmg"
