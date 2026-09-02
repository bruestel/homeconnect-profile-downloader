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
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    let plist = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../packaging/macos/hcpd-login-Info.plist");
    println!("cargo:rerun-if-changed={}", plist.display());
    println!("cargo:rustc-link-arg=-Wl,-sectcreate,__TEXT,__info_plist,{}", plist.display());
}
