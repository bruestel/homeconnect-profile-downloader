#!/usr/bin/env bash
#
# Builds the AppImage.
#
#   packaging/linux/make-appimage.sh 2.0.0
#
# An AppImage is a directory with a fixed shape and a runtime bolted on the
# front. The shape is the whole of the work here: a .desktop file and an icon at
# the top level, both named after the application, and an AppRun that starts it.
#
# Downloads appimagetool if it is not already beside this script, because it
# ships as an AppImage rather than as a package.

set -euo pipefail

version=${1:?give me a version}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)

name="Home_Connect_Profile_Downloader"
appdir="$root/dist/AppDir"
# The architecture is asked of the machine rather than assumed. appimagetool
# ships one build per architecture and names the result after it, and a file
# called x86_64 holding aarch64 binaries is worse than no file.
arch=$(uname -m)
tool="$here/appimagetool-$arch"

rm -rf "$appdir"
mkdir -p "$appdir/usr/bin" "$appdir/usr/share/applications" \
         "$appdir/usr/share/icons/hicolor"

# Both binaries. The application looks for the helper beside itself.
install -m 755 "$root/target/release/hcpd" "$appdir/usr/bin/hcpd"
install -m 755 "$root/target/release/hcpd-login" "$appdir/usr/bin/hcpd-login"

install -m 644 "$here/hcpd.desktop" "$appdir/usr/share/applications/hcpd.desktop"
cp -r "$root/packaging/icon/rendered/hicolor/." "$appdir/usr/share/icons/hicolor/"

# The top level wants its own copies under exactly these names. A missing one is
# reported by appimagetool as a shape error rather than a missing file.
cp "$here/hcpd.desktop" "$appdir/hcpd.desktop"
cp "$root/packaging/icon/rendered/hicolor/256x256/apps/hcpd.png" "$appdir/hcpd.png"
ln -sf hcpd.png "$appdir/.DirIcon"

cat > "$appdir/AppRun" <<'APPRUN'
#!/bin/sh
# The helper is found beside the binary, so the binary is what is run, from
# inside the mounted image.
HERE=$(dirname "$(readlink -f "$0")")
exec "$HERE/usr/bin/hcpd" "$@"
APPRUN
chmod +x "$appdir/AppRun"

if [ ! -x "$tool" ]; then
    echo "fetching appimagetool"
    curl -fsSL -o "$tool" \
        "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-$arch.AppImage"
    chmod +x "$tool"
fi

mkdir -p "$root/dist"
# No FUSE on a CI runner, so the tool is asked to extract itself instead of
# mounting. ARCH is not guessed by the tool when it runs this way.
ARCH="$arch" "$tool" --appimage-extract-and-run "$appdir" \
    "$root/dist/$name-$version-$arch.AppImage"

rm -rf "$appdir"
echo "written: $root/dist/$name-$version-$arch.AppImage"
