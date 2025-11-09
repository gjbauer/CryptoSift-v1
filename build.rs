extern crate bindgen;
use bindgen::CargoCallbacks;
use std::env;
use std::path::PathBuf;

fn main() {
	let bindings = bindgen::Builder::default()
		.header("src/tiny-AES-c/aes.h")
		.clang_arg("-DAES256")
		.parse_callbacks(Box::new(CargoCallbacks::new()))
		.generate()
		.expect("Unable to generate bindings");

	let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
	bindings
		.write_to_file(out_path.join("bindings.rs"))
		.expect("Couldn't write bindings!");
	
	cc::Build::new()
	.file("src/tiny-AES-c/aes.c")
	.flag("-DAES256")
	.compile("tiny-AES-c");
}
