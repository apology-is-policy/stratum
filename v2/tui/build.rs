// Build script: locate the cmake-built libstm_9p_client + its
// dependencies and emit cargo:rustc-link-* directives.
//
// Tries `STM_BUILD_DIR` env var first (CI / test harness convention),
// then falls back to `../build` (manual dev workflow: build the C
// tree once with `cmake --build build`, then `cargo build` inside
// `tui/`).
use std::env;
use std::path::PathBuf;

fn main() {
    let candidates: Vec<PathBuf> = match env::var("STM_BUILD_DIR") {
        Ok(p) => vec![PathBuf::from(p)],
        Err(_) => vec![
            PathBuf::from("../build"),
            PathBuf::from("../../build"),
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
        None => {
            panic!(
                "could not find libstm_9p_client.a — set STM_BUILD_DIR \
                 or run `cmake --build build` from the v2 root"
            );
        }
    };

    // Search paths.
    println!("cargo:rustc-link-search=native={}", build_dir.join("src/9p_client").display());
    println!("cargo:rustc-link-search=native={}", build_dir.join("src/9p").display());
    println!("cargo:rustc-link-search=native={}", build_dir.join("src/cmd/stratumd").display());
    println!("cargo:rustc-link-search=native={}", build_dir.join("src/util").display());
    println!("cargo:rustc-link-search=native={}", build_dir.display());

    // Libraries — order matters for static linking.
    println!("cargo:rustc-link-lib=static=stm_9p_client");

    // Re-run if the C lib changes.
    println!("cargo:rerun-if-changed={}", build_dir.join("src/9p_client/libstm_9p_client.a").display());
    println!("cargo:rerun-if-changed=../include/stratum/9p_client.h");
    println!("cargo:rerun-if-env-changed=STM_BUILD_DIR");
}
