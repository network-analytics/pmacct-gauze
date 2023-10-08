use bindgen_bridge::export::Template;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

type Result<T> = core::result::Result<T, Box<dyn Error>>;

fn main() -> Result<()> {
    let mut template = Template::new("cbindgen.toml.template");
    let template = template
        .read_as_toml()?
        .with_bindings(&pmacct_gauze_bindings::bindings_renames_aliased);

    let out_file = PathBuf::from("cbindgen.toml");
    let mut file = File::create(&out_file)?;

    file.write_all(template.config_header()?.as_bytes())?;
    file.write_all(template.generate_toml()?.to_string().as_bytes())?;

    println!("Output cbindgen.toml at: {:?}", out_file);

    Ok(())
}
