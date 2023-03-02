# SMTools
 Tools for Sourcemodders using Binary Ninja

### Features
- Supports both IDA and Sourcemod signature encodings
- Fast `O(N)` signature generation

### Installation

- Clone the repository
- Run `cargo build --release`
- Copy the compiled `.dll` or `.so` into BinaryNinja's `plugins` directory
- Restart binary ninja (if open)