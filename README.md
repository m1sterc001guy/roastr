# `fedimimtd` build with custom module set (example)

`fedimintd` is modular and extendable: 3rd party developers can write
custom functionality in form of Fedimint modules on top of the consensus
and infrastructure of Fedimint.

This repository is meant to be a simple starting example for
people who want to develop and use 3rd party Fedimint modules.

`fedimintd` modules are Rust crates that need to be compiled
with the `fedimintd` crate (the library it provides).
See `./fedimintd/src/main.rs`.


### Building

This crate heavily re-uses the Nix building system of core Fedimintd
(see `flake.nix`). 3rd party developers and user might want to replace
it with their preferred building system. Compiling `fedimintd` is just
like compiling any other Rust project with some C dependencies, so
using Nix is not required, but used for simplicity and convenience.

To enter Fedimint nix dev shell run `nix develop`. This will reproducibly
set up all the required libraries and dependencies. Then run
`cargo build --release` to compile `fedimintd`.

Use `nix build -L .#` to build a custom `fedimintd` Nix package. The
the output will be pointed at by `./result` symlink.
