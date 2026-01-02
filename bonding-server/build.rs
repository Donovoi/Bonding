use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    // Only run on Windows
    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "windows" {
        return;
    }

    // Get the architecture
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    // Determine wintun.dll path based on architecture
    let wintun_dll_name = match arch.as_str() {
        "x86_64" => "wintun_amd64.dll",
        "x86" => "wintun_x86.dll",
        "aarch64" => "wintun_arm64.dll",
        "arm" => "wintun_arm.dll",
        _ => {
            println!("cargo:warning=Unsupported architecture for Wintun embedding: {arch}");
            return;
        }
    };

    // Look for wintun.dll in project resources directory
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let project_root = manifest_dir.parent().unwrap();
    let resources_dir = project_root.join("resources");
    let wintun_path = resources_dir.join(wintun_dll_name);

    // Generate code to embed the DLL if it exists
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let gen_file = out_dir.join("embedded_wintun.rs");

    let mut file = fs::File::create(&gen_file).expect("Failed to create generated file");

    if wintun_path.exists() {
        let path_str = wintun_path.to_str().expect("Path contains invalid UTF-8");

        writeln!(
            file,
            "/// Embedded wintun DLL bytes (compiled into binary)\npub const EMBEDDED_WINTUN_DLL: Option<&[u8]> = Some(include_bytes!(r\"{}\"));",
            path_str
        )
        .expect("Failed to write generated code");

        println!("cargo:rerun-if-changed={}", wintun_path.display());
        println!(
            "cargo:warning=Server will embed Wintun DLL: {} ({} bytes)",
            wintun_dll_name,
            fs::metadata(&wintun_path).unwrap().len()
        );
    } else {
        writeln!(
            file,
            r#"
/// Embedded wintun DLL bytes (not available - will need to be provided at runtime)
pub const EMBEDDED_WINTUN_DLL: Option<&[u8]> = None;
"#
        )
        .expect("Failed to write generated code");

        println!(
            "cargo:warning=wintun.dll not found at {}.",
            wintun_path.display()
        );
        println!("cargo:warning=The server binary will require wintun.dll at runtime on Windows.");
        println!(
            "cargo:warning=To embed wintun.dll for the server, place {} in {} before building.",
            wintun_dll_name,
            resources_dir.display()
        );
    }
}
