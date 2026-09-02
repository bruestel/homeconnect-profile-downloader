# Packaging

Two binaries, five packages, three systems. Everything here exists to get
`hcpd` and `hcpd-login` onto a machine **side by side**, because the
application looks for the helper next to itself and an install with only one of
them is an install that cannot sign in.

| System | What is built | By |
| --- | --- | --- |
| Linux | `.deb` | `cargo deb`, configured in `app/Cargo.toml` |
| | `.rpm` | `cargo generate-rpm`, same place |
| | AppImage | `linux/make-appimage.sh` |
| | Arch | `aur/PKGBUILD`, built from your own clone |
| Windows | installer | `windows/hcpd.nsi`, NSIS |
| macOS | `.dmg` | `macos/make-dmg.sh` |

`.github/workflows/release.yml` runs all of it on a tag and hangs the results on
a draft release. A manual run builds the packages and publishes nothing, which
is what makes it safe for trying the packaging out.

## The icon

`icon/hcpd.svg` is the drawing, `icon/make-icons.sh` renders everything else,
and the results in `icon/rendered/` are **committed**. Two reasons: renderers
differ enough between machines that the same SVG comes out slightly
differently, and a release should not depend on librsvg being installed on a
runner. Change the SVG, run the script, look at what came out, commit it.

The directory is `rendered` rather than `out` because a bare `out` rule in the
repository's `.gitignore`, left from the Electron build, silently swallowed it.

## Architectures

| System | x86_64 | aarch64 |
| --- | --- | --- |
| Linux | `ubuntu-22.04` | `ubuntu-22.04-arm` |
| Windows | `windows-latest` | `windows-11-arm` |
| macOS | cross-built on the arm runner | native |

Native runners on Linux and Windows rather than cross-compilation, because the
build needs webkit2gtk's headers and libraries and getting those into a cross
sysroot is a project of its own. macOS is the exception: there the only library
involved is the system's own WebKit and the SDK carries both architectures, so
one runner builds both.

**macOS gets two images, not one universal one.** Five megabytes each against ten
of which half is dead weight on any given machine. They are named `intel` and
`apple-silicon`, because that is what a person knows about their own Mac.

Linux on aarch64 is there because this is a tool for people running openHAB or
Home Assistant, and some of them are on a Pi.

**None of the ARM runners has been tried.** The three ARM rows above are written
from documentation, not from a run, and two things could plausibly be wrong: the
runner labels, and whether NSIS is installed on the Windows ARM image at the
path the workflow uses. A `workflow_dispatch` run builds everything and
publishes nothing, which is the way to find out.

The `Build` workflow that runs on every push stays on x86_64 only. Covering four
more machines on every commit costs more than it catches, and the manual release
run is the check before a tag.

## Things that are decided, and why

**Nothing is signed.** The Electron version was not either. On macOS Gatekeeper
will stop the first launch, and a person has to open it from the context menu
once; on Windows SmartScreen reports an unknown publisher. Both need a paid
certificate and neither depends on the package format.

The macOS bundle *is* signed ad-hoc, with `codesign --sign -`. That is not a
certificate and gets past nothing. It only stops macOS refusing to run an
unsigned bundle at all on Apple silicon.

**Linux is built on Ubuntu 22.04**, not on the newest runner. A binary is bound
to the glibc it was built against, so building on the newest would produce
packages that refuse to start on the release before it. Both libraries the
build needs are available there, checked rather than assumed:
`libwebkit2gtk-4.1-dev` is 2.50.4 on jammy.

**The Windows installer is per user**, into `%LOCALAPPDATA%\Programs`, so it
needs no administrator and raises no prompt. A tool that downloads a file into
your own folder has no business writing to Program Files.

**The settings file survives uninstallation.** It holds a region and a folder,
it is tiny, and removing it would surprise anyone who reinstalls.

**The Arch package is not published to the AUR.** It is here so anyone on Arch
can build their own, which is one command and needs no account, no trust in a
third party's build, and nothing kept in step with a second repository. It
packages the clone it is sitting in, at the checked-out branch's HEAD.

## Building one by hand

```sh
cargo build --release --workspace

# Linux
cargo deb -p hcpd --no-build -o dist/
cargo generate-rpm -p app -o dist/
packaging/linux/make-appimage.sh 2.0.0

# Arch
cd packaging/aur && makepkg -si

# macOS, on macOS
packaging/macos/make-dmg.sh 2.0.0

# Windows, with NSIS
mkdir -p dist/stage && cp target/release/hcpd.exe target/release/hcpd-login.exe dist/stage/
makensis -DVERSION=2.0.0 packaging/windows/hcpd.nsi
```

Everything lands in `dist/`, which is not tracked.

## What has actually been built

| | |
| --- | --- |
| `.deb`, `.rpm`, AppImage | built on Arch, and the AppImage starts |
| macOS `.dmg` | built in the QEMU guest, mounted, dragged to Applications, and started from there |
| Arch package | built with `makepkg`, and both binaries out of it run |
| Windows installer | built in the VM, installed, started, uninstalled |

What the Windows run confirmed: both binaries land in
`%LOCALAPPDATA%\Programs\hcpd` side by side, the Start Menu shortcut is
written, the uninstall entry carries the right name, version and publisher, the
installed application opens its window, and a silent uninstall removes all
three again. No elevation prompt anywhere, which is the point of installing per
user.

What the macOS run confirmed, beyond that the script works: the signature
verifies, `CFBundleName` reaches the menu bar, the icon is in the bundle, and
the mounted image holds the application beside a link to `/Applications`.

One thing it did **not** confirm, and cannot: Gatekeeper. An image built and
mounted on the same machine carries no quarantine flag, so it opens without a
word. A person downloading the same file gets the flag and the warning, and
that only changes with a paid certificate.
