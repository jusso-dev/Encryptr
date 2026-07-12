//! Generate the OpenAPI spec from the code-first `ApiDoc` and write it to
//! `docs/openapi.yaml` and `docs/openapi.json`.
//!
//! Run `cargo run --bin gen-openapi` to regenerate after changing any handler
//! annotation or DTO. CI runs the same command and fails if the checked-in
//! files differ (see `.github/workflows/ci.yml`).

use std::path::Path;

use encryptr_server::api::openapi::ApiDoc;

fn main() -> std::io::Result<()> {
    let docs = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs");
    std::fs::create_dir_all(&docs)?;

    let yaml = ApiDoc::as_yaml();
    let json = ApiDoc::as_json();
    std::fs::write(docs.join("openapi.yaml"), yaml)?;
    std::fs::write(docs.join("openapi.json"), format!("{json}\n"))?;

    println!("wrote docs/openapi.yaml and docs/openapi.json");
    Ok(())
}
