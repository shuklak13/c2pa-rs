// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Example App that generates a manifest store listing for a given file
use anyhow::Result;
#[cfg(not(target_arch = "wasm32"))]
use c2pa::ManifestStore;

// Ensure that the URI contains a manifest reference, and if not, add one.
#[cfg(not(target_arch = "wasm32"))]
fn to_absolute_uri(manifest_label: &str, uri: &str) -> String {
    const ABSOLUTE_JUMBF_PREFIX: &str = "self#jumbf=/c2pa/";
    if !uri.starts_with(ABSOLUTE_JUMBF_PREFIX) {
        if let Some(pos) = uri.find('=') {
            let uri = format!(
                "{}{}/{}",
                ABSOLUTE_JUMBF_PREFIX,
                manifest_label,
                &uri[pos + 1..]
            );
            return uri;
        }
    };
    uri.to_string()
}

#[cfg(not(target_arch = "wasm32"))]
fn redact_thumbnails(
    manifest_store: &ManifestStore,
    manifest_label: &str,
    redactions: &mut Vec<String>,
) {
    if let Some(manifest) = manifest_store.get(manifest_label) {
        if let Some(thumbnail_ref) = manifest.thumbnail_ref() {
            let thumb_uri = to_absolute_uri(manifest_label, &thumbnail_ref.identifier);
            println!("redacting claim thumbnail: {}", thumb_uri);
            redactions.push(thumb_uri);
        }
        for ingredient in manifest.ingredients() {
            if let Some(thumbnail_ref) = ingredient.thumbnail_ref() {
                let thumb_uri = to_absolute_uri(manifest_label, &thumbnail_ref.identifier);
                println!("redacting ingredient thumbnail: {}", thumb_uri);
                redactions.push(thumb_uri);
            }
        }
    } else {
        println!("Manifest not found {}", manifest_label);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn main() -> Result<()> {
    use c2pa::{create_signer, Ingredient, IngredientOptions, Manifest, ResourceRef, SigningAlg};
    struct Options {}
    impl IngredientOptions for Options {
        fn thumbnail(&self, _path: &std::path::Path) -> Option<(String, Vec<u8>)> {
            None
        }
    }
    let options = Options {};
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 2 {
        let source = &args[1];
        let dest = &args[2];
        let manifest_store = ManifestStore::from_file(source)?;
        if let Some(manifest_label) = manifest_store.active_label() {
            let mut redactions = Vec::new();
            redact_thumbnails(&manifest_store, manifest_label, &mut redactions);
            let mut manifest = Manifest::new("redaction_test/0.1");
            let mut parent = Ingredient::from_file_with_options(source, &options)?;
            //parent.set_relationship(Relationship::parentOf);
            parent.set_is_parent();
            manifest.set_parent(parent)?;
            for redaction in redactions {
                manifest.add_redaction(redaction)?;
            }
            // force no claim thumbnail generation
            manifest.set_thumbnail_ref(ResourceRef::new("none", "none"))?;
            // sign and embed into the target file
            let signcert_path = "sdk/tests/fixtures/certs/es256.pub";
            let pkey_path = "sdk/tests/fixtures/certs/es256.pem";
            let signer =
                create_signer::from_files(signcert_path, pkey_path, SigningAlg::Es256, None)?;

            manifest.embed(&source, &dest, &*signer)?;

            let manifest_store = ManifestStore::from_file(dest)?;
            println!(
                "redactions: {:?}",
                manifest_store.get_active().unwrap().redactions()
            );

            // example of how to print out the whole manifest as json
            println!("{manifest_store}\n");
        } else {
            println!("No c2pa manifest found in file");
        }

        println!("{manifest_store}");
    } else {
        println!("Redacts thumbnails from file (requires an input file and an output file path argument)")
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn main() -> Result<()> {
    Ok(())
}
