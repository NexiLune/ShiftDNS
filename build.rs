#[path = "src/icon_gen.rs"]
mod icon_gen;

fn main() {
    println!("cargo:rerun-if-changed=app.manifest");
    println!("cargo:rerun-if-changed=src/icon_gen.rs");

    #[cfg(target_os = "windows")]
    {
        let out_dir = std::env::var_os("OUT_DIR").expect("OUT_DIR not set");
        let ico_path = std::path::PathBuf::from(out_dir).join("shiftdns.ico");
        if let Err(err) = icon_gen::write_ico_file(&ico_path) {
            println!("cargo:warning=Failed to generate shiftdns.ico: {err}");
        }

        let mut res = winresource::WindowsResource::new();
        res.set_manifest_file("app.manifest");
        res.set("FileDescription", "ShiftDNS")
            .set("ProductName", "ShiftDNS")
            .set("InternalName", "ShiftDNS")
            .set("OriginalFilename", "ShiftDNS.exe");
        if ico_path.exists() {
            res.set_icon(ico_path.to_string_lossy().as_ref());
        }
        if let Err(err) = res.compile() {
            println!("cargo:warning=Failed to embed Windows resources: {err}");
        }
    }
}
