use std::fs;
use std::io;

fn main() -> io::Result<()> {
	let file_path = "dump.bin";

	let bytes = fs::read(file_path)?;

	// Now 'bytes' contains the binary data as a Vec<u8>
	println!("Read {} bytes from the file.", bytes.len());

	// You can iterate through the bytes or process them as needed
	for byte in bytes.iter().take(10) { // Print the first 10 bytes as an example
		print!("{:02X} ", byte);
	}
	println!();

	Ok(())
}
