## Eclipse Biscuit C API

This crate provides a C API for the Eclipse Biscuit token library. It is a wrapper around the Rust API, and is intended to be used by other languages that can interface with C.

### Building from sources

To build the C API, you need to have the Rust toolchain installed. You can then build the C API by running:

```sh
cargo cinstall --release --prefix=/path/to/install --destdir=/path/to/destdir
```
It will produce a shared library in the `--destdir` directory and also the C headers.
You can then link against the generated library in your C code.

`cargo cinstall` is provided by the [`cargo-c`](https://github.com/lu-zero/cargo-c/) crate, which you can install with `cargo install cargo-c`.

### Downloading pre-built binaries
In the [releases section](https://github.com/biscuit-auth/biscuit-rust/releases) of this repository, you can find pre-built binaries for the C API.
Currently, only Linux x86_64 and MacOS (arm) are provided.

### Running the tests

```sh
cargo ctest
```

## License

Licensed under Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be licensed as above, without any additional terms or
conditions.
