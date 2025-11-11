# CryptoSift-v1: A successful failure

## Background

A Cold Boot Attack is when somebody who has access to a machine
which is encrypted, but has already been turned on and decrypted,
and which does not employ specific mitigations such as a secure
enclave or memory zeroing on startup, is able to freeze the
machine's RAM to increase data remanance and boot into a custom
application designed to scrape the contents of the RAM into
a physical dump file containing the contents of the system's RAM.

The individual is then able to search the contents of the data
dump to look for a potential key and associated key schedule.

After successfully locating the key in the data dump, the
individual is then able to decrypt the drive with the discovered
key without having to know the passphrase.

## What failed in this iteration...

This program was an attempt at locating a key and associated 
key schedule in a data dump, tested using QEMU. The methodology
employed here was unable to find a key and associated schedule in
the data dump.

I was able to verify that the key and key schedule did in fact
exist in the dump by utilizing the tool `findaes`.

In my second attempt, I will start my attempting to re-write
`findaes` in Rust as both a library and application. I intend
to utilize the library version of the code to integrate into
my revitalized CryptoSift application.

### What about bit rot?

This is an important consideration and will likely render
the `findaes-rs` library insufficient on its own. I will likely
need to fork my own re-write into some kind of `aesreconstruct`
which will search for potential keys and then check if the
associated potential key schedule falls within a maximum
Hamming distance of the key schedule generated from the original
potential key.

If it does not, I will have to implement a way of systematically
flipping bits (a maximum number of bits flipped aka a maximum
Hamming distance for the key itself will be defined) and then 
calculate the Hamming distance between the newly generated key
schedule and the potential key schedule. If it falls within the
set maximum Hamming distance, we have likely found our key!!

## What was successfuly about this iteration...

Though I was unable to achieve the original desired result, this
attempt taught me a lot of very valuable things about coding
in Rust and about certain algorithms.

Things I learned more about include:

 - Multi-threading and fearless concurrency in Rust
 - Message passing as implemented in Rust
 - The FFI (or Foreign Function Interface)
 - Shannon Entropy calculation

What I learned throughout the process of developing this, albeit
unsuccessful attempt, will almost certainly be of value as I continue
my journey of learning to develop software in Rust and as I move onto
the second iteration of this tool...
