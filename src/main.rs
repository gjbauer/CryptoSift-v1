/* MIT License
 *
 * Copyright (c) 2025 gjbauer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::fs;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::error::Error;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

impl AES_ctx {
    pub fn new() -> Self {
        AES_ctx { RoundKey: [0; 240], Iv: [0; 16] }
    }
}

#[derive(Clone)]
struct PotentialKey
{
	bytes: Vec<u8>,
	entropy: f32
}

struct Message
{
	progress: usize,
	id: usize
}

struct Sender
{
	tx: Option<mpsc::Sender<Message>>,
	id: usize
}

fn filter_memory_dump(bytes: &[u8], chunk_size: Option<usize>, stride: Option<usize>, tx: Sender) -> Vec<PotentialKey>
{
	let actual_stride = stride.unwrap_or_else(|| 4);
	let actual_chunk_size = chunk_size.unwrap_or_else(|| 64);
	let mut keys: Vec<PotentialKey> = Vec::new();
	
	for i in (0..=bytes.len()-actual_chunk_size-240).step_by(actual_stride)
	{
		if !tx.tx.is_none() { tx.tx.clone().unwrap().send(Message { progress: i, id: tx.id} ).unwrap(); }
		let vec = bytes[i..i+actual_chunk_size].to_vec();
		
		// Filter 1: Skip known compressed formats
		if is_known_compressed_format(&vec) {
			continue;
		}
		
		// Filter 2: Minimum entropy threshold
		let entropy = calculate_entropy(&vec);
		if entropy < 4.75 {
			continue;
		}
		
		/*//Filter 3: AES Rounds Keys
		let maybe_key = is_potential_key(&bytes[i..i+actual_chunk_size+240]);
		if !maybe_key {
			continue;
		}*/
		
		keys.push(PotentialKey { bytes: vec.clone(), entropy: entropy });
		keys.sort_by(|a, b| b.entropy.total_cmp(&a.entropy));
		if keys.len() > 256 { keys.pop(); }
	}
	
	drop(tx);
	keys
}

fn filter_potential_keys(pks: &[PotentialKey], bytes: &Vec<u8>, tx: Sender) -> Vec<PotentialKey>
{
	let mut filtered = Vec::new();
	for (i, pk) in pks.iter().enumerate() {
		tx.tx.clone().unwrap().send(Message { progress: i, id: tx.id }).unwrap();
		if is_potential_key(&pk.bytes, bytes) {
			filtered.push(pk.clone());
		}
	}
	filtered
}

fn is_potential_key(key: &Vec<u8>, bytes: &Vec<u8>) -> bool
{
	let mut all_bytes_found: bool = false;
	let mut ctx = generate_round_keys(&key[0..32]);
	for k in 0..15 {
		let start = k*(ctx.RoundKey.len()/15);
		let mut end = (k+1)*(ctx.RoundKey.len()/15);
		if k == 14 { end = ctx.RoundKey.len(); }
		for i in 0..bytes.len()-16 {
			for j in start..end {
				if ctx.RoundKey[j..j+1] == bytes[i+(j-start)..i+(j-start)+1]{
					all_bytes_found = true;
				}
				else {
					all_bytes_found = false;
					break;
				}
			}
			if all_bytes_found {
				break;
			}
		}
		if !all_bytes_found {
			return false;
		} else {
			println!("All bytes found for first key...");
		}
	}
	ctx = generate_round_keys(&key[32..64]);
	/*for k in 0..15 {
		let start = k*(ctx.RoundKey.len()/15);
		let mut end = (k+1)*(ctx.RoundKey.len()/15);
		if k == 14 { end = ctx.RoundKey.len(); }
		for i in 0..bytes.len()-16 {
			for j in start..end {
				if ctx.RoundKey[j..j+1] == bytes[i+(j-start)..i+(j-start)+1]{
					all_bytes_found = true;
				}
				else {
					all_bytes_found = false;
					break;
				}
			}
			if all_bytes_found {
				break;
			}
		}
		if !all_bytes_found {
			return false;
		} else {
			println!("All bytes found for second key...");
		}
	}*/
	
	all_bytes_found
}

fn generate_round_keys(slice: &[u8]) -> AES_ctx
{
	let master_key = slice.as_ptr();
	let mut ctx = AES_ctx::new();
	let raw_ctx: *mut AES_ctx = &mut ctx;
	unsafe {
		AES_init_ctx(raw_ctx, master_key);
	}
	ctx
}

fn is_known_compressed_format(data: &Vec<u8>) -> bool
{
	// GZIP (.gz, .tar.gz)
	let mut all_bytes_found: bool = false;
	for i in 0..data.len() {
		for j in 0..b"\x1f\x8b".len() {
			if data[i] == b"\x1f\x8b"[j] {
				all_bytes_found = true;
			}
			else {
				all_bytes_found = false;
			}
		}
	}
	if all_bytes_found { return all_bytes_found; }
	// BZIP2 (.bz2, .tar.bz2) 
	for i in 0..data.len() {
		for j in 0..b"BZh".len() {
			if data[i] == b"BZh"[j] {
				all_bytes_found = true;
			}
			else {
				all_bytes_found = false;
			}
		}
	}
	if all_bytes_found { return all_bytes_found; }
	// XZ (.xz, .tar.xz)
	for i in 0..data.len() {
		for j in 0..b"\xfd7zXZ\x00".len() {
			if data[i] == b"\xfd7zXZ\x00"[j] {
				all_bytes_found = true;
			}
			else {
				all_bytes_found = false;
			}
		}
	}
	if all_bytes_found { return all_bytes_found; }
	// ZIP (.zip, .jar, .docx)
	for i in 0..data.len() {
		for j in 0..b"PK\x03\x00".len() {
			if data[i] == b"PK\x03\x00"[j] {
				all_bytes_found = true;
			}
			else {
				all_bytes_found = false;
			}
		}
	}
	if all_bytes_found { return all_bytes_found; }
	// 7-Zip (.7z)
	for i in 0..data.len() {
		for j in 0..b"7z\xbc\xaf\x27\x1c".len() {
			if data[i] == b"7z\xbc\xaf\x27\x1c"[j] {
				all_bytes_found = true;
			}
			else {
				all_bytes_found = false;
			}
		}
	}
	if all_bytes_found { return all_bytes_found; }
	// RAR (.rar)
	for i in 0..data.len() {
		for j in 0..b"Rar!\x1a\x07\x00".len() {	// RAR v1.5+
			if data[i] == b"Rar!\x1a\x07\x00"[j] {
				all_bytes_found = true;
			}
			else {
				all_bytes_found = false;
			}
		}
	}
	if all_bytes_found { return all_bytes_found; }
	for i in 0..data.len() {
		for j in 0..b"Rar!\x1a\x07\x01".len() {	// RAR v5.0
			if data[i] == b"Rar!\x1a\x07\x01"[j] {
				all_bytes_found = true;
			}
			else {
				all_bytes_found = false;
			}
		}
	}
	if all_bytes_found { return all_bytes_found; }
	
	// Image formats (often compressed)
	for i in 0..data.len() {
		for j in 0..b"\xff\xd8\xff".len() {	// JPEG
			if data[i] == b"\xff\xd8\xff"[j] {
				all_bytes_found = true;
			}
			else {
				all_bytes_found = false;
			}
		}
	}
	if all_bytes_found { return all_bytes_found; }
	for i in 0..data.len() {
		for j in 0..b"\x89PNG\r\n\x1a\n".len() {	// PNG
			if data[i] == b"\x89PNG\r\n\x1a\n"[j] {
				all_bytes_found = true;
			}
			else {
				all_bytes_found = false;
			}
		}
	}
	if all_bytes_found { return all_bytes_found; }
	for i in 0..data.len() {
		for j in 0..b"GIF8".len() {	// GIF87a or GIF89a
			if data[i] == b"GIF8"[j] {
				all_bytes_found = true;
			}
			else {
				all_bytes_found = false;
			}
		}
	}
	if all_bytes_found { return all_bytes_found; }
	
	// PDF (often contains compressed streams)
	for i in 0..data.len() {
		for j in 0..b"%PDF-".len() {	// PDF
			if data[i] == b"%PDF-"[j] {
				all_bytes_found = true;
			}
			else {
				all_bytes_found = false;
			}
		}
	}
	if all_bytes_found { return all_bytes_found; }
	
	// Executable formats (can have compressed sections)
	// Could check for UPX-packed executables specifically
	for i in 0..data.len() {
		for j in 0..b"\x7fELF".len() {	// ELF binary
			if data[i] == b"\x7fELF"[j] {
				all_bytes_found = true;
			}
			else {
				all_bytes_found = false;
			}
		}
	}
	if all_bytes_found { return all_bytes_found; }
	for i in 0..data.len() {
		for j in 0..b"MZ".len() {	// Windows PE
			if data[i] == b"MZ"[j] {
				all_bytes_found = true;
			}
			else {
				all_bytes_found = false;
			}
		}
	}
	return all_bytes_found;
}

fn calculate_entropy(bytes: &Vec<u8>) -> f32
{
	let mut counts: [u32; 256] = [0; 256];
	
	for byte in bytes {
		counts[*byte as usize] += 1;
	}
	
	let mut entropy = 0.0;
	for count in counts {
		let prob: f32 = count as f32 / bytes.len() as f32;
		if prob > 0.0 {
			entropy -= prob * prob.log2();
		}
	}
	
	return entropy;
}

fn main() -> Result<(), Box<dyn Error>> {
	let args: Vec<String> = std::env::args().collect();
	let mut chunk_size: Option<usize> = None;
	let mut stride: Option<usize> = None;
	let usage = r#"cryptosift: Cold Boot Data Processing and Encryption Forensics Tool
Copyright (c) 2025 Gabriel Bauer All rights reserved.
Usage:
	cryptosift [options] /path/to/data-dump /path/to/keyfile-out/directory"#;
	if args.len() < 3 {
		println!("{}", usage.to_string());
		std::process::exit(1);
	}
	else if args.len() > 3 {
		for i in (1..=args.len()-2).step_by(2) {
			if args[i] == "-cs" {
				chunk_size = args[i+1].parse().ok();
			}
			if args[i] == "-st" {
				stride = args[i+1].parse().ok();
			}
		}
	}
	
	let output_dir = &args[args.len() - 1];
	let file_path = &args[args.len() - 2];

	let bytes = Arc::new(fs::read(file_path)?);
	let (tx, rx): (mpsc::Sender<Message>, mpsc::Receiver<Message>) = mpsc::channel();
	
	let mut children = vec![];
	
	for i in 0..=15 {
		let bytes_clone = Arc::clone(&bytes);
		let tx_clone = tx.clone();
		// Spin up another thread
		children.push(thread::spawn(move || {
		let mut end = (i+1)*(bytes_clone.len()/16);
		if i == 15 { end = bytes_clone.len(); }
		let slice = &bytes_clone[i*(bytes_clone.len()/16)..end];
		return filter_memory_dump(slice, chunk_size, stride, Sender{ tx: Some(tx_clone), id: i });
		}));
	}
	drop(tx);
	
	let mut queue = vec![];
	for received_message in &rx {
		queue.retain(|item: &Message| item.id != received_message.id);
		queue.push(received_message);
		let j: usize = queue.iter().map(|s| s.progress).sum();
		print!("{:3.2} % into entropy and known-compreesed types tests...\r", (100.0 * j as f32 / bytes.len() as f32));
	}
	drop(rx);
	println!("100.00 % into entropy and known-compreesed types tests...");
	
	println!("Processing area between threads");
	for i in 0..=14 {
		let bytes_clone = Arc::clone(&bytes);
		// Spin up another thread
		children.push(thread::spawn(move || {
		let slice = &bytes_clone[(i+1)*(bytes_clone.len()/16)-240..(i+1)*(bytes_clone.len()/16)+240];
		return filter_memory_dump(slice, chunk_size, stride, Sender{ tx: None, id: i });
		}));
	}
	println!("Entropy and known-compression tests finished!!");

	let mut keys_super = vec![];
	for child in children {
		// Wait for the thread to finish. Returns a result.
		let output = child.join();
		keys_super.push(output);
	}
	
	let mut keys: Arc<Vec<PotentialKey>> = Arc::new(keys_super.into_iter().flat_map(|result| result.unwrap_or_else(|_| Vec::new())).collect());
	
	println!("Found {} potential keys!!", keys.len());
	
	if let Some(keys_ref) = Arc::get_mut(&mut keys) {
		keys_ref.sort_by(|a, b| b.entropy.total_cmp(&a.entropy));
	}
	
	children = vec![];
	
	let (tx, rx): (mpsc::Sender<Message>, mpsc::Receiver<Message>) = mpsc::channel();
	
	for i in 0..8 {
		let bytes_clone = Arc::clone(&bytes);
		let keys_clone = Arc::clone(&keys);
		let tx_clone = tx.clone();
		// Spin up another thread
		children.push(thread::spawn(move || {
		let mut end = (i+1)*(keys_clone.len()/8);
		if i == 7 { end = keys_clone.len(); }
		let slice = &keys_clone[i*(keys_clone.len()/8)..end];
		return filter_potential_keys(slice, &bytes_clone, Sender{ tx: Some(tx_clone), id: i });
		}));
	}
	drop(tx);
	
	queue = vec![];
	for received_message in &rx {
		queue.retain(|item: &Message| item.id != received_message.id);
		queue.push(received_message);
		let j: usize = queue.iter().map(|s| s.progress).sum();
		print!("{:3.2} % into round keys tests...\r", (100.0 * j as f32 / keys.len() as f32));
	}
	drop(rx);
	println!("100.00 % into round keys tests...");
	
	let mut final_keys_super = vec![];
	for child in children {
		// Wait for the thread to finish. Returns a result.
		let output = child.join();
		final_keys_super.push(output);
	}
	
	let mut final_keys: Vec<PotentialKey> = final_keys_super.into_iter().flat_map(|result| result.unwrap_or_else(|_| Vec::new())).collect();
	final_keys.sort_by(|a, b| b.entropy.total_cmp(&a.entropy));
	
	println!("Memory dump processed!!");
	
	println!("Filtered to {} potential keys!!", final_keys.len());
	
	if final_keys.len() > 0 { println!("Writing potential keys to files in directory..."); }
	
	for i in 0..final_keys.len() {
		fs::write(output_dir.to_string()+"/"+&i.to_string()+".bin", &final_keys[i].bytes)?;
	}

	Ok(())
}
