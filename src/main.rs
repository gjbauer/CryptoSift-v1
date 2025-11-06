use std::fs;
use std::io;
use std::collections::BTreeMap;
use std::thread;

// def scan_memory_dump(file_path: str, device: str, candidates: list = [], chunk_size: int = 32, stride: int = 8):
/*fn scan_memory_dump(file_path: String, device: String)
{
	// TODO: Implement scanning function!!!
}*/

fn calculate_entropy(bytes: &Vec<u8>) -> f32
{
	let mut counts = BTreeMap::new();
	for i in 0..=255 {
		counts.insert(i, 0);
	}
	
	for byte in bytes {
		if let Some(count) = counts.get_mut(&byte) {
			*count += 1;
		}
	}
	
	let mut entropy = 0.0;
	for count in counts.values() {
		let prob: f32 = *count as f32 / bytes.len() as f32;
		if prob > 0.0 {
			entropy -= prob * prob.log2();
		}
	}
	
	print!("{:.2} ", entropy);
	
	return entropy;
}

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
	
	println!("bytes per thread {}", bytes.len()/16);
	
	let mut children = vec![];
	
	for i in 0..=15 {
		// Spin up another thread
		children.push(thread::spawn(move || {
		println!("this is thread number {}", i);
		}));
	}

	for child in children {
		// Wait for the thread to finish. Returns a result.
		let _ = child.join();
	}
	
	calculate_entropy(&bytes);
	
	calculate_entropy(&bytes);

	Ok(())
}
