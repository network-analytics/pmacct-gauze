use bindgen::callbacks::{MacroParsingBehavior, ParseCallbacks};
use bindgen_bridge::import::{NameMappings, NameMappingsCallback};
use std::cell::RefCell;
use std::collections::HashSet;
use std::env;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::Rc;

#[derive(Debug)]
struct IgnoreMacros(HashSet<String>);

impl ParseCallbacks for IgnoreMacros {
    fn will_parse_macro(&self, name: &str) -> MacroParsingBehavior {
        if self.0.contains(name) {
            MacroParsingBehavior::Ignore
        } else {
            MacroParsingBehavior::Default
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let header_location = option_env!("PMACCT_HEADER_DIR").unwrap_or("/usr/local/include/pmacct");

    // Tell cargo to look for shared libraries in the specified directory
    println!(
        "cargo:rustc-link-search={}",
        option_env!("LINK_SEARCH_DIR").unwrap_or("/usr/local/lib")
    );

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=imported.h");

    println!("Running build.rs");

    let ignored_macros = IgnoreMacros(
        vec![
            "FP_INFINITE".into(),
            "FP_NAN".into(),
            "FP_NORMAL".into(),
            "FP_SUBNORMAL".into(),
            "FP_ZERO".into(),
            "IPPORT_RESERVED".into(),
        ]
        .into_iter()
        .collect(),
    );

    let name_mappings = Rc::new(RefCell::new(NameMappings::default()));
    let name_mappings_cb = Box::new(NameMappingsCallback(name_mappings.clone()));

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("imported.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .parse_callbacks(Box::new(ignored_macros))
        .parse_callbacks(name_mappings_cb)
        //.c_naming(true)
        //.depfile("netgauze", "/tmp/depfile")
        .allowlist_file(format!("{header_location}/src/bmp/bmp.h"))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    let mut name_mappings = name_mappings.take();
    name_mappings.forget_unused_aliases();
    println!("discovered mappings = {:#?}", name_mappings);

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");

    println!("Using file output to : {:?}", &out_path);

    bindings
        .write_to_file(&out_path)
        .expect("Couldn't write bindings!");

    if cfg!(feature = "export-renames") {
        export_renames(name_mappings, &out_path)?;
    }

    println!("Output path for bindings : {:?}", out_path);

    Ok(())
}

fn export_renames(name_mappings: NameMappings, out_path: &PathBuf) -> bindgen_bridge::Result<()> {
    let mut codegen = name_mappings.codegen();
    let codegen = codegen.as_static_map(cfg!(feature = "static-renames"));

    let bindings_renames = codegen
        .variable_name(Some("bindings_renames"))
        .use_aliases(false)
        .generate()?
        .to_string();

    println!("generated renames [no aliases] = \n{}", bindings_renames);

    let bindings_renames_aliased = codegen
        .variable_name(Some("bindings_renames_aliased"))
        .use_aliases(true)
        .generate()?
        .to_string();

    println!(
        "generated renames [yes aliases] = \n{}",
        bindings_renames_aliased
    );

    append_file(bindings_renames_aliased.as_bytes(), out_path, true)
        .expect("Couldn't write bindings renames unaliased!");

    append_file(bindings_renames.as_bytes(), out_path, true)
        .expect("Couldn't write bindings renames aliased!");

    println!("Added export renames for cbindgen.toml!");

    Ok(())
}

fn append_file<P: AsRef<Path> + ?Sized>(
    data: &[u8],
    path: &P,
    line_break: bool,
) -> Result<(), Box<dyn Error>> {
    let mut f = OpenOptions::new().write(true).append(true).open(path)?;

    f.write_all(data)?;

    if line_break {
        f.write_all(b"\n")?;
    }

    Ok(())
}
