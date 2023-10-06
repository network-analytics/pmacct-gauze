use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use toml::Table;
use toml_edit::{Document, Formatted, Item, table};

type Result<T> = core::result::Result<T, Box<dyn Error>>;

fn read_toml_table<P: AsRef<Path> + ?Sized>(path: &P) -> Result<Document> {
    let mut file = File::open(path).expect("cbindgen.toml not found");

    let mut content = if let Ok(metadata) = file.metadata() {
        String::with_capacity(metadata.len() as usize)
    } else {
        String::new()
    };

    file.read_to_string(&mut content)?;

    Ok(Document::from_str(content.as_str())?)
}

fn get_bindings_rename_toml() -> Result<Table> {
    let renames: &'static str = pmacct_gauze_bindings::get_bindings_renames_aliased();

    let table: Table = toml::from_str(renames)?;

    Ok(table)
}

fn main() -> Result<()> {
    let template_path = "cbindgen.toml.template";
    let mut cbindgen = read_toml_table(template_path)?;
    println!("cbindgen.toml : {:#?}", cbindgen);

    let bindings = get_bindings_rename_toml()?;
    println!("bindings.toml : {:#?}", bindings);

    let renames = if let Some(table) = cbindgen.get_mut("export.rename") {
        table.as_table_mut().unwrap()
    } else {
        cbindgen["export"]["rename"] = table();
        cbindgen["export"]["rename"].as_table_mut().unwrap()
    };

    bindings.into_iter().for_each(|(rust_name, c_name)| {
        // need this to escape the string quotes
        let c_name_text = c_name.as_str().unwrap().to_string();
        let item = Item::Value(toml_edit::Value::String(Formatted::new(c_name_text)));
        renames.insert(
            rust_name.as_str(),
            item
        );
    });

    println!("new renames = {:#?}", cbindgen["export"]["rename"].as_table_mut());

    println!("final config = {}", cbindgen.to_string());

    let out_file = PathBuf::from("cbindgen.toml");
    let mut file = File::create(&out_file)?;
    file.write_all(generated_config_header(template_path).as_bytes())?;

    file.write_all(cbindgen.to_string().as_bytes())?;

    println!("Output cbindgen.toml at: {:?}", out_file);

    Ok(())
}

fn generated_config_header(template_path: &str) -> String {
    format!("# This configuration file has been automatically generated\n\
    # Do not modify it manually. Instead, make changes to its associated template : {template_path}\n\n")
}