// Locate cmake-built libstm_9p_client + emit cargo:rustc-link-* directives.
// Mirrors v2/tui/build.rs but the candidate paths are adjusted for the
// extra directory level (we're at v2/tools/stratum-slate-tty/).
use std::env;
use std::path::PathBuf;

fn main() {
    let candidates: Vec<PathBuf> = match env::var("STM_BUILD_DIR") {
        Ok(p) => vec![PathBuf::from(p)],
        Err(_) => vec![
            PathBuf::from("../../build"),
            PathBuf::from("../../../build"),
            PathBuf::from("../build"),
        ],
    };

    let mut build_dir: Option<PathBuf> = None;
    for c in &candidates {
        let probe = c.join("src").join("9p_client").join("libstm_9p_client.a");
        if probe.exists() {
            build_dir = Some(c.canonicalize().unwrap_or(c.clone()));
            break;
        }
    }
    let build_dir = match build_dir {
        Some(p) => p,
        None => panic!(
            "could not find libstm_9p_client.a — set STM_BUILD_DIR or run \
             `cmake --build build` from the v2 root"
        ),
    };

    println!("cargo:rustc-link-search=native={}", build_dir.join("src/9p_client").display());
    println!("cargo:rustc-link-search=native={}", build_dir.join("src/9p").display());
    println!("cargo:rustc-link-search=native={}", build_dir.display());

    println!("cargo:rustc-link-lib=static=stm_9p_client");

    println!("cargo:rerun-if-changed={}", build_dir.join("src/9p_client/libstm_9p_client.a").display());
    println!("cargo:rerun-if-env-changed=STM_BUILD_DIR");
}
