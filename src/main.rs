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

use std::fs;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::error::Error;
use std::io::prelude::*;
use flate2::Compression;
use flate2::write::ZlibEncoder;

#[derive(Clone)]
struct PotentialKey
{
	bytes: Vec<u8>,
	meta_score: f32
}

struct Message
{
	progress: usize,
	id: usize
}

struct Sender
{
	tx: mpsc::Sender<Message>,
	id: usize
}

fn scan_memory_dump(bytes: &[u8], chunk_size: Option<usize>, stride: Option<usize>, compression: bool, tx: Sender) -> Vec<PotentialKey>
{
	let actual_stride = stride.unwrap_or_else(|| 4);
	let actual_chunk_size = chunk_size.unwrap_or_else(|| 32);
	let mut keys: Vec<PotentialKey> = Vec::new();
	
	for i in (0..=bytes.len()-actual_chunk_size).step_by(actual_stride)
	{
		tx.tx.send(Message { progress: i, id: tx.id} ).unwrap();
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
		
		let mut ratio: f32 = 0.0;
		if compression {
			// Filter 3: Minimum compression threshold
			ratio = calculate_compression_ratio(&vec);
			if ratio < 1.3 {
				continue;
			}
		}
		
		keys.push(PotentialKey { bytes: vec.clone(), meta_score: calculate_meta_score(entropy, ratio, compression) });
		keys.sort_by(|a, b| b.meta_score.total_cmp(&a.meta_score));
		if keys.len() > 128 { keys.pop(); }
	}
	
	drop(tx);
	keys
}

fn is_known_compressed_format(data: &Vec<u8>) -> bool
{
	// GZIP (.gz, .tar.gz)
	if b"\x1f\x8b".iter().all(|item| data.contains(item)) {
		return true;
	}
	// BZIP2 (.bz2, .tar.bz2) 
	if b"BZh".iter().all(|item| data.contains(item)) {
		return true;
	}
	// XZ (.xz, .tar.xz)
	if b"\xfd7zXZ\x00".iter().all(|item| data.contains(item)) {
		return true;
	}
	// ZIP (.zip, .jar, .docx)
	if b"PK\x03\x00".iter().all(|item| data.contains(item)) {
		return true;
	}
	// 7-Zip (.7z)
	if b"7z\xbc\xaf\x27\x1c".iter().all(|item| data.contains(item)) {
		return true;
	}
	// RAR (.rar)
	if b"Rar!\x1a\x07\x00".iter().all(|item| data.contains(item)) {	// RAR v1.5+
		return true;
	}
	if b"Rar!\x1a\x07\x01".iter().all(|item| data.contains(item)) {	// RAR v5.0
		return true;
	}
	
	// Image formats (often compressed)
	if b"\xff\xd8\xff".iter().all(|item| data.contains(item)) {	// JPEG
		return true;
	}
	if b"\x89PNG\r\n\x1a\n".iter().all(|item| data.contains(item)) {	// PNG
		return true;
	}
	if b"GIF8".iter().all(|item| data.contains(item)) {	// GIF87a or GIF89a
		return true;
	}
	
	// PDF (often contains compressed streams)
	if b"%PDF-".iter().all(|item| data.contains(item)) {	// PDF
		return true;
	}
	
	// Executable formats (can have compressed sections)
	// Could check for UPX-packed executables specifically
	if b"\x7fELF".iter().all(|item| data.contains(item)) {	// ELF binary
		return true;
	}
	if b"MZ".iter().all(|item| data.contains(item)) {	// Windows PE
		return true;
	}
	
	return false;
}

fn calculate_meta_score(entropy: f32, ratio: f32, compression: bool) -> f32
{
	if compression { return ((entropy/8.0)*0.7) + (ratio*0.3); }
	else { return entropy/8.0; }
}

fn calculate_compression_ratio(bytes: &Vec<u8>) -> f32
{
	let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
	let _ = e.write_all(&bytes[0..bytes.len()]);
	let cmp_bytes = e.finish().unwrap();
	return cmp_bytes.len() as f32 / bytes.len() as f32;
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
	let mut compression = true;
	let usage = r#"cryptosift: Cold Boot Data Processing and Encryption Forensics Tool
Copyright (c) 2025 Gabriel Bauer All rights reserved.
Usage:
	cryptosift [options] /path/to/data-dump /path/to/keyfile-out/directory"#;
	if args.len() < 3 {
		println!("{}", usage.to_string());
		std::process::exit(1);
	}
	else if args.len() > 3 {
		for mut i in 1..=args.len()-2 {
			if args[i] == "-cs" {
				chunk_size = args[i+1].parse().ok();
				i += 1;
			}
			if args[i] == "-st" {
				stride = args[i+1].parse().ok();
				i += 1;
			}
			if args[i] == "-nc" {
				compression = false;
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
		return scan_memory_dump(slice, chunk_size, stride, compression, Sender{ tx: tx_clone, id: i });
		}));
	}
	drop(tx);
	
	let mut queue = vec![];
	for received_message in rx {
		queue.retain(|item: &Message| item.id != received_message.id);
		queue.push(received_message);
		let j: usize = queue.iter().map(|s| s.progress).sum();
		print!("{:3.2} % into dump...\r", (100 * j as f32 / bytes.len() as f32));
	}
	println!("100 % into dump...");
	println!("Dump processed!!");

	let mut keys_super = vec![];
	for child in children {
		// Wait for the thread to finish. Returns a result.
		let output = child.join();
		keys_super.push(output);
	}
	let mut keys: Vec<PotentialKey> = keys_super.into_iter().flat_map(|result| result.unwrap_or_else(|_| Vec::new())).collect();
	
	keys.sort_by(|a, b| b.meta_score.total_cmp(&a.meta_score));
	
	println!("Writing potential keys to files in directory...");
	
	for i in 0..keys.len() {
		fs::write(output_dir.to_string()+"/"+&i.to_string()+".bin", &keys[i].bytes)?;
	}

	Ok(())
}
