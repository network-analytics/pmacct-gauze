use std::collections::HashSet;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use quote::quote;

#[derive(Debug)]
struct IgnoreMacros(HashSet<String>);

impl bindgen::callbacks::ParseCallbacks for IgnoreMacros {
    fn will_parse_macro(&self, name: &str) -> bindgen::callbacks::MacroParsingBehavior {
        if self.0.contains(name) {
            bindgen::callbacks::MacroParsingBehavior::Ignore
        } else {
            bindgen::callbacks::MacroParsingBehavior::Default
        }
    }
}

fn main() {
    // Tell cargo to look for shared libraries in the specified directory
    println!("cargo:rustc-link-search=/usr/local/lib");

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

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("imported.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .parse_callbacks(Box::new(ignored_macros))
        .c_naming(true)
        .depfile("netgauze", "/tmp/depfile")
        .allowlist_file("/usr/local/include/pmacct/src/bmp/bmp.h")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the src/bindings.rs file because we want autocomplete in our IDE.
    let out_path = if cfg!(feature = "source-bindings") {
        PathBuf::from("src")
    } else {
        PathBuf::from(env::var("OUT_DIR").unwrap())
    };
    let out_path = out_path.join("bindings.rs");

    println!("Output path for bindings : {:?}", out_path);

    let warning_allows = quote! {
        #![allow(non_upper_case_globals)]
        #![allow(non_camel_case_types)]
        #![allow(non_snake_case)]
        #![allow(improper_ctypes)]
    };

    bindings
        .write_to_file(&out_path)
        .expect("Couldn't write bindings!");

    if cfg!(feature = "source-bindings") {
        prepend_file(warning_allows.to_string().as_ref(), &out_path, true)
            .expect("Couldn't write bindings allows!");
    }
}

fn prepend_file<P: AsRef<Path> + ?Sized>(data: &[u8], path: &P, line_break: bool) -> Result<(), Box<dyn Error>> {
    let mut f = File::open(path)?;
    let mut content = data.to_owned();
    f.read_to_end(&mut content)?;

    let mut f = File::create(path)?;
    f.write_all(content.as_slice())?;

    if line_break {
        f.write_all(b"\n")?;
    }

    Ok(())
}