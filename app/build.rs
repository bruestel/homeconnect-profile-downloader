//! Gives the binary a name on macOS.
//!
//! A bare executable has no bundle, so the menu bar shows the file name. The
//! linker can put a plist into the `__TEXT,__info_plist` section, which macOS
//! reads exactly as it reads a bundle's, and the name comes out right whether
//! this runs from `target/release` or from inside the `.app`.
//!
//! The check is on `CARGO_CFG_TARGET_OS` and not on `cfg!(target_os)`: a build
//! script runs on the machine doing the building, so `cfg` here would answer
//! for the host and get cross-compilation backwards.

fn main() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    decode_icon(root);

    match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("macos") => {
            let plist = root.join("../packaging/macos/hcpd-Info.plist");
            println!("cargo:rerun-if-changed={}", plist.display());
            println!(
                "cargo:rustc-link-arg=-Wl,-sectcreate,__TEXT,__info_plist,{}",
                plist.display()
            );
        }
        Ok("windows") => {
            // Windows reads an executable's icon out of a resource inside the
            // file. A .ico beside it, or named in the installer, is not enough:
            // the shortcut points at the executable and takes what is in there.
            let icon = root.join("../packaging/icon/rendered/hcpd.ico");
            println!("cargo:rerun-if-changed={}", icon.display());

            let mut resource = winresource::WindowsResource::new();
            resource.set_icon(icon.to_str().expect("the path is text"));
            resource.set("ProductName", "Home Connect Profile Downloader");
            resource.set("FileDescription", "Home Connect Profile Downloader");
            resource.set("LegalCopyright", "Copyright (c) Jonas Bruestel");
            resource.compile().expect("the resource compiles");
        }
        _ => {}
    }
}

/// Turns the icon into raw pixels beside the build, so the binary can carry it
/// without linking an image decoder to read a PNG it already knows.
///
/// The window icon matters on X11 and Windows, where it is a property of the
/// window itself. Wayland has no such property: there the desktop matches the
/// window to its `.desktop` entry by application id and takes the icon from
/// there, which is why `linux_identity` exists as well. Both are needed, and
/// neither replaces the other.
fn decode_icon(root: &std::path::Path) {
    let source = root.join("../packaging/icon/rendered/hicolor/256x256/apps/hcpd.png");
    println!("cargo:rerun-if-changed={}", source.display());

    let file = std::fs::File::open(&source).expect("the icon is where it is expected");
    let decoder = png::Decoder::new(std::io::BufReader::new(file));
    let mut reader = decoder.read_info().expect("the icon is a PNG");
    let mut pixels = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut pixels).expect("the icon has a frame");

    assert_eq!(info.color_type, png::ColorType::Rgba, "the icon has to carry an alpha channel");
    pixels.truncate(info.buffer_size());

    let out = std::path::Path::new(&std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"))
        .join("icon.rgba");
    std::fs::write(&out, &pixels).expect("the pixels are written");
    println!("cargo:rustc-env=HCPD_ICON_SIZE={}", info.width);
}
