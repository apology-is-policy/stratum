// build.rs — discover every static lib produced by the cmake build and
// emit cargo link directives. Order is auto-resolved by the host
// linker (macOS ld is smart; Linux ld gets --start-group/--end-group).
//
// The set of libs is the same set the cmake `stratum` INTERFACE
// library aggregates (v2/CMakeLists.txt :211), plus the four cmd
// run-main libs (libstm_cmd_<name>.a) the SWISS-1 chunk introduced.

use std::env;
use std::fs;
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

    // Locate the build dir by probing for libstm_9p_client.a.
    let build_dir = candidates
        .iter()
        .find(|c| c.join("src/9p_client/libstm_9p_client.a").exists())
        .map(|p| p.canonicalize().unwrap_or_else(|_| p.clone()))
        .unwrap_or_else(|| {
            panic!(
                "could not find v2/build/ — set STM_BUILD_DIR or run \
                 `cmake --build build` from the v2 root"
            )
        });

    // Walk v2/build/src/** + v2/build/third_party/ for libstm_*.a / libblake3.a / libxxhash.a.
    // Each unique parent dir gets a search path; each lib gets a -l directive.
    let mut search_dirs: Vec<PathBuf> = Vec::new();
    let mut lib_names: Vec<String> = Vec::new();

    let mut stack: Vec<PathBuf> = vec![
        build_dir.join("src"),
        build_dir.join("third_party"),
    ];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Skip CMakeFiles internals.
                if path.file_name().is_some_and(|f| f == "CMakeFiles") {
                    continue;
                }
                stack.push(path);
            } else if let Some(name) = path.file_name().and_then(|f| f.to_str()) {
                if let Some(libname) = parse_static_lib_name(name) {
                    if let Some(parent) = path.parent() {
                        if !search_dirs.iter().any(|p| p == parent) {
                            search_dirs.push(parent.to_path_buf());
                        }
                    }
                    if !lib_names.iter().any(|n| n == &libname) {
                        lib_names.push(libname);
                    }
                }
            }
        }
    }

    // Emit search paths.
    for dir in &search_dirs {
        println!("cargo:rustc-link-search=native={}", dir.display());
    }

    // On Linux, wrap the lib list in --start-group/--end-group so the
    // linker can resolve circular deps between libstm_* libs. macOS
    // ld auto-resolves; no need for the wrapping there.
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let needs_group = matches!(target_os.as_str(), "linux" | "android" | "freebsd");
    if needs_group {
        println!("cargo:rustc-link-arg=-Wl,--start-group");
    }
    for lib in &lib_names {
        println!("cargo:rustc-link-lib=static={lib}");
    }
    if needs_group {
        println!("cargo:rustc-link-arg=-Wl,--end-group");
    }

    // System deps mirror what the cmake `stratum` aggregate pulls in.
    if target_os == "linux" {
        println!("cargo:rustc-link-lib=dylib=pthread");
        println!("cargo:rustc-link-lib=dylib=dl");
        println!("cargo:rustc-link-lib=dylib=m");
    }
    // libsodium is required by libstm_crypto. The cmake build uses
    // pkg-config; we mirror that so cargo can find it on macOS
    // (Homebrew default) + Linux (system / pkg-config).
    pkgconfig_link("libsodium").expect("libsodium not found via pkg-config");

    // Re-run if any .a changes.

    // Re-run if any .a changes.
    for dir in &search_dirs {
        println!("cargo:rerun-if-changed={}", dir.display());
    }
    println!("cargo:rerun-if-env-changed=STM_BUILD_DIR");
    println!("cargo:rerun-if-changed={}", build_dir.display());
}

/// Return the lib name (between `lib` prefix and `.a` suffix) if `f`
/// looks like a static library we should link.
fn parse_static_lib_name(f: &str) -> Option<String> {
    let stem = f.strip_prefix("lib")?.strip_suffix(".a")?;
    // Skip the test-only lib; production binary doesn't want it.
    if stem == "stm_testlib" {
        return None;
    }
    Some(stem.to_string())
}

/// Invoke `pkg-config --cflags --libs <name>` and emit cargo link
/// directives. Returns Ok(()) on success.
fn pkgconfig_link(name: &str) -> Result<(), String> {
    use std::process::Command;
    let out = Command::new("pkg-config")
        .args(["--libs", name])
        .output()
        .map_err(|e| format!("pkg-config: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "pkg-config --libs {name} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    for tok in s.split_whitespace() {
        if let Some(rest) = tok.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={rest}");
        } else if let Some(rest) = tok.strip_prefix("-l") {
            println!("cargo:rustc-link-lib=dylib={rest}");
        }
    }
    Ok(())
}
