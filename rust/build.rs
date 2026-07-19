fn main() {
    println!("cargo:rerun-if-env-changed=LIBKRUNFW_LIB_DIR");

    // Native-only builds must remain usable without libkrun installed.
    if std::env::var_os("CARGO_FEATURE_VM").is_some() {
        guest_init_build::configure();
        let library = pkg_config::Config::new()
            .atleast_version("1.19")
            .probe("libkrun")
            .unwrap_or_else(|error| {
                panic!(
                    "libkrun >= 1.19 not found: {e}. Install via:\n  \
                 macOS:  brew install libkrun\n  \
                 Linux:  see https://github.com/libkrun/libkrun",
                    e = error
                )
            });

        match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
            Ok("macos") => configure_macos_vm_linking(&library),
            Ok("linux") => {
                println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/../lib/cdm");
            }
            _ => {}
        }
    }
}

#[path = "guest-init/build-support/artifact.rs"]
mod guest_init_artifact;
#[path = "guest-init/build-support.rs"]
mod guest_init_build;

fn configure_macos_vm_linking(library: &pkg_config::Library) {
    use std::path::{Path, PathBuf};

    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("aarch64") {
        panic!("libkrun VM mode on macOS requires Apple silicon (aarch64)");
    }

    // Release packages place both VM libraries beside the executable under
    // ../lib/cdm. Keep a build-machine path as a development fallback only.
    println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path/../lib/cdm");

    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("LIBKRUNFW_LIB_DIR") {
        candidates.push(PathBuf::from(path));
    }
    candidates.extend(library.link_paths.iter().cloned());

    for link_path in &library.link_paths {
        if let Some(homebrew_prefix) = homebrew_prefix_from_cellar(link_path) {
            candidates.push(homebrew_prefix.join("lib"));
        }
    }
    candidates.extend([
        PathBuf::from("/opt/homebrew/lib"),
        PathBuf::from("/usr/local/lib"),
    ]);
    candidates.sort();
    candidates.dedup();

    if let Some((directory, framework)) = candidates.into_iter().find_map(|directory| {
        ["libkrunfw.5.dylib", "libkrunfw.dylib"]
            .iter()
            .map(|name| directory.join(name))
            .find(|path| path.is_file())
            .map(|framework| (directory, framework))
    }) {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", directory.display());
        println!("cargo:rerun-if-changed={}", framework.display());
        return;
    }

    panic!(
        "libkrunfw was not found. Install it with Homebrew or set \
         LIBKRUNFW_LIB_DIR to the directory containing libkrunfw.5.dylib"
    );

    fn homebrew_prefix_from_cellar(path: &Path) -> Option<PathBuf> {
        let components = path.components().collect::<Vec<_>>();
        let cellar = components
            .iter()
            .position(|component| component.as_os_str() == "Cellar")?;
        Some(components[..cellar].iter().collect())
    }
}
