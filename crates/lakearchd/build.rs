//! Build-Skript: kompiliert die gRPC-Service-Definition (`proto/lakearch.proto`)
//! mit `tonic-prost-build` zu Rust-Code.
//!
//! In dieser Umgebung ist **kein** System-`protoc` installiert. Wir setzen daher
//! die `PROTOC`-Umgebungsvariable auf das von `protoc-bin-vendored`
//! mitgelieferte, vorgebaute Binär — so braucht weder `tonic-build`/`prost-build`
//! noch der CI ein System-`protoc` (siehe `DECISIONS-FOR-REVIEW.md`,
//! Transport-Entscheidung).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Das mitgelieferte protoc-Binär finden und prost/tonic darauf verweisen.
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: build.rs läuft single-threaded vor jeder Nebenläufigkeit; das Setzen
    // von PROTOC ist der dokumentierte Weg, prost/tonic ein protoc vorzugeben.
    unsafe {
        std::env::set_var("PROTOC", &protoc);
    }

    // Nur neu generieren, wenn sich die .proto-Datei ändert.
    println!("cargo:rerun-if-changed=proto/lakearch.proto");
    println!("cargo:rerun-if-changed=build.rs");

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/lakearch.proto"], &["proto"])?;
    Ok(())
}
