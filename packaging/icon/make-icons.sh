#!/usr/bin/env bash
#
# Renders every icon the three systems want, from packaging/icon/hcpd.svg.
#
#   packaging/icon/make-icons.sh
#
# The results are committed rather than built in CI, for two reasons: the
# renderers differ enough between machines that the same SVG comes out slightly
# differently, and a release should not depend on librsvg being installed on a
# runner. Run this when the SVG changes, look at what came out, and commit it.
#
# Needs rsvg-convert and ImageMagick.

set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
out="$here/rendered"

# Two drawings, and which one a size gets is the whole reason this script has a
# function instead of a loop. Below 32 pixels the appliance's door and panel are
# two or three pixels each and blur into a smudge, so those sizes draw the arrow
# alone.
#
# The threshold is on the *logical* size, which matters on macOS: a 16pt icon at
# double density is 32 pixels of the small drawing, not the appliance.
SMALL_UP_TO=24

drawing() {
    if [ "$1" -le "$SMALL_UP_TO" ]; then echo "$here/hcpd-small.svg"; else echo "$here/hcpd.svg"; fi
}

# render <output> <pixels> [logical size, if it differs]
render() {
    local file=$1 pixels=$2 logical=${3:-$2}
    rsvg-convert -w "$pixels" -h "$pixels" "$(drawing "$logical")" -o "$file"
}

command -v rsvg-convert >/dev/null || { echo "rsvg-convert is missing" >&2; exit 1; }
command -v magick >/dev/null || { echo "ImageMagick is missing" >&2; exit 1; }

rm -rf "$out"
mkdir -p "$out/hicolor"

# Linux: one PNG per size, laid out the way hicolor wants them.
for size in 16 24 32 48 64 128 256 512; do
    mkdir -p "$out/hicolor/${size}x${size}/apps"
    render "$out/hicolor/${size}x${size}/apps/hcpd.png" "$size"
done
# The scalable one is the appliance: anything asking for it has room. It goes
# where hicolor wants it, beside the sized ones, so that copying the tree is
# enough and no consumer has to know it sits somewhere else.
mkdir -p "$out/hicolor/scalable/apps"
cp "$here/hcpd.svg" "$out/hicolor/scalable/apps/hcpd.svg"

# Windows: every size in one file, because the shell picks per context and a
# 256 scaled down by the shell looks worse than a 16 drawn as one.
ico_sizes=()
for size in 16 24 32 48 64 128 256; do
    render "$out/ico-$size.png" "$size"
    ico_sizes+=("$out/ico-$size.png")
done
magick "${ico_sizes[@]}" "$out/hcpd.ico"
rm -f "$out"/ico-*.png

# macOS: an iconset directory, which is what iconutil takes. The .icns itself is
# built on the macOS runner, because iconutil is the only thing that writes one
# Finder is entirely happy with.
iconset="$out/hcpd.iconset"
mkdir -p "$iconset"
# Third argument where the logical size differs from the pixel count: a 16pt
# icon is the small drawing whether it is rendered at 16 or at 32.
render "$iconset/icon_16x16.png" 16 16
render "$iconset/icon_16x16@2x.png" 32 16
render "$iconset/icon_32x32.png" 32 32
render "$iconset/icon_32x32@2x.png" 64 32
render "$iconset/icon_128x128.png" 128 128
render "$iconset/icon_128x128@2x.png" 256 128
render "$iconset/icon_256x256.png" 256 256
render "$iconset/icon_256x256@2x.png" 512 256
render "$iconset/icon_512x512.png" 512 512
render "$iconset/icon_512x512@2x.png" 1024 512

echo "written to $out"
find "$out" -type f | sed "s|$out/||" | sort
