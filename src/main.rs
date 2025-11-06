use std::fs;
use std::io;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread;

struct PotentialKey
{
	pos: u64,
	bytes: Vec<u8>,
	entropy: f32
}

// def scan_memory_dump(file_path: str, device: str, candidates: list = [], chunk_size: int = 32, stride: int = 8):
fn scan_memory_dump(bytes: &[u8], chunk_size: Option<usize>, stride: Option<usize>) -> Vec<PotentialKey>
{
	let actual_stride = stride.unwrap_or_else(|| 16);
	let actual_chunk_size = chunk_size.unwrap_or_else(|| 32);
	// TODO: Implement scanning function!!!
	let mut keys: Vec<PotentialKey> = Vec::new();
	
	for i in (0..=bytes.len()-actual_chunk_size).step_by(actual_stride)
	{
		//print!("{:3.2} % into dump...\r", (100 * i / (bytes.len()-actual_chunk_size)));
		// TODO: Implement message passing to calculate total work by all threads...nice to have, but not our top priority at the moment...
		
		// Filter 2: Minimum entropy threshold
		let entropy = calculate_entropy(&bytes[i..i+actual_chunk_size]);
		if entropy < 4.65 {
			continue;
		}
	}
	println!();
	/*
	for i in range(0, len(data) - chunk_size, stride):
		print("{:.2f}".format(100 * (i / (len(data) - chunk_size)))+" % into dump...", end="\r", flush=True)
		chunk = data[i:i + chunk_size]
		
		# Filter 1: Skip known compressed formats
		if is_known_compressed_format(chunk):
			continue
			
		# Filter 2: Minimum entropy threshold
		entropy = calculate_entropy(chunk)
		if entropy < 4.65:
			continue
		
		print("\nPotential key with entropy {:.2f}".format(entropy))
		candidates.append((i, chunk, entropy))
		# Sort by entropy + compression ratio (most promising first)
		candidates.sort(key=lambda x: (x[2]), reverse=True)
		if len(candidates) > 64:
			candidates.pop()  # Remove lowest entropy candidate
	*/
	
	keys
}

fn calculate_entropy(bytes: &[u8]) -> f32
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
	
	println!("{:.2} ", entropy);
	
	return entropy;
}

fn main() -> io::Result<()> {
	let file_path = "dump.bin";

	let bytes = Arc::new(fs::read(file_path)?);

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
		let bytes_clone = Arc::clone(&bytes);
		// Spin up another thread
		children.push(thread::spawn(move || {
		println!("this is thread number {}", i);
		let slice = &bytes_clone[i..(i+1)*(bytes_clone.len()/16)];
		scan_memory_dump(slice, None, None);
		}));
	}

	for child in children {
		// Wait for the thread to finish. Returns a result.
		let _ = child.join();
	}
	
	//calculate_entropy(&bytes);
	
	//calculate_entropy(&bytes);

	Ok(())
}
