use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use bindgen::CompKind;
use proc_macro2::Ident;
use quote::quote;
use std::fmt::Write as fmt_Write;

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

#[derive(Debug, Default, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(transparent)]
struct Type(usize);

#[derive(Debug, Default, Eq, PartialEq)]
struct NameMapping {
    /// This is optional because of anonymous types
    c_name: Option<String>,
    rust_name: String,
    aliases: HashSet<String>,
}

impl NameMapping {
    pub fn build_c_name(kind: CompKind, original_name: Option<&str>) -> Option<String> {
        let original_name = original_name?;

        // has a space
        let prefix = match kind {
            CompKind::Struct => "struct ",
            CompKind::Union => "enum "
        };

        let result = if original_name.starts_with(prefix) {
            original_name.to_string()
        } else {
            format!("{prefix}{original_name}")
        };

        Some(result)
    }
}

#[derive(Debug, Default)]
struct NameMappings {
    types: HashMap<Type, NameMapping>,
    aliases: HashMap<Type, HashSet<String>>,
}

impl NameMappings {
    pub fn forget_unused_aliases(&mut self) -> usize {
        self.aliases.drain().map(|(_, set)| set.len()).sum()
    }


    /// generate a cbindgen.toml [export.rename] section, without the section header
    pub fn to_cbindgen_toml_renames(&self, use_aliases: bool) -> Result<String, Box<dyn Error>> {
        let mut result = String::with_capacity(self.types.len() * 16); // rough approximate of the capacity

        for (id, mapping) in &self.types {
            let use_name = if mapping.c_name.is_none() || (use_aliases && !mapping.aliases.is_empty()) {
                mapping.aliases.iter().next()
            } else {
                mapping.c_name.as_ref()
            };

            if let Some(use_name) = use_name {
                writeln!(&mut result, "\"{}\" = \"{}\"", mapping.rust_name, use_name)?;
            } else {
                eprintln!("Warn: type with no valid name during rename export! id={} info={:#?}", id.0, mapping);
                continue
            }
        }

        Ok(result)
    }
}

#[derive(Debug)]
struct NameMappingsCallback(Rc<RefCell<NameMappings>>);

/// types: Map ItemId => Info { canonical_ident (final rust name), original_name(item.kind.type.name), HashSet<Alias> }
/// found_aliases: Map ItemId => Alias
/// on new type/item: call new composite callback => insert to map, check found_aliases
/// on new alias: call new alias callback => if alias.type in types types.get(alias.type.id).push_alias(alias) else found_aliases.push(alias)
/// on resolvedtyperef: call new alias callback => ^ + typeref.name != original_name
impl bindgen::callbacks::ParseCallbacks for NameMappingsCallback {
    fn new_composite_found(&self, _id: usize, _kind: CompKind, _original_name: Option<&str>, _final_ident: &Ident) {
        let mut mappings = self.0.borrow_mut();

        let id = Type(_id);
        let mut aliases = mappings.aliases.remove(&id).unwrap_or_else(|| HashSet::new());

        let mut c_name = NameMapping::build_c_name(_kind, _original_name);

        println!("kind : {:?} original {:?} => {:?}", _kind, _original_name, c_name);
        // if the struct is not anonymous, remove all aliases with the same name
        if c_name.is_some() {
            aliases.retain(|value| !value.eq(c_name.as_deref().unwrap()));
        }
        // if the struct is anonymous we use one of the already known aliases as a name for it
        else if let Some(one_alias) = aliases.iter().next().cloned() {
            c_name = aliases.take(&one_alias)
        }

        if let Some(duplicate) = mappings.types.insert(id, NameMapping {
            c_name: c_name.clone(), // may still be unknown in case of anonymous struct without known aliases
            rust_name: _final_ident.to_string(),
            aliases,
        }) {
            println!("Warn: duplicated definition for {{ id={} name={:?} }}! previous: {:?}", _id, c_name, duplicate)
        }
    }

    fn new_alias_found(&self, _id: usize, _alias_name: &Ident, _alias_for: usize) {
        let mut mappings = self.0.borrow_mut();

        let target_id = Type(_alias_for);
        let aliased_name = _alias_name.to_string();

        if let Some(mapping) = mappings.types.get_mut(&target_id) {
            // if the structure was anonymous let's use one of its aliases as a name
            if let None = mapping.c_name {
                mapping.c_name = Some(aliased_name.clone());
            }
            // if it wasn't, remember the alias
            else {
                mapping.aliases.insert(aliased_name);
            }
        } else {
            mappings.aliases.entry(target_id).or_default().insert(aliased_name);
        };
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
        .depfile("netgauze", "/tmp/depfile")
        .allowlist_file("/usr/local/include/pmacct/src/bmp/bmp.h")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    let mut name_mappings = name_mappings.take();
    name_mappings.forget_unused_aliases();
    println!("discovered mappings = {:#?}", name_mappings);
    println!("generated renames [no aliases] = \n{}", name_mappings.to_cbindgen_toml_renames(false).unwrap());
    println!("generated renames [yes aliases] = \n{}", name_mappings.to_cbindgen_toml_renames(true).unwrap());

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