# ROASTr Technical Reference Documentation

## Target audience

This documentation is automatically generated from the ROASTr source code,
and it's meant for developers, builders and people who want to understand
the ROASTr project on an implementation level.

If you are looking for higher level documentation and help, please check:

* [Fedimint website](https://fedimint.org/)
* [Fedimint github](https://github.com/fedimint/fedimint)
* [Fedimint chat](https://chat.fedimint.org/)

## State

This is a recently added document and subject of continuous change. Please report problems and submit improvements.

# Overview

Fedimint is implemented in [Rust](https://www.rust-lang.org/) and consists of multiple Rust crates.
On a high-level Fedimint architecture consist of:

* Server side: [`fedimintd`](./fedimintd/index.html) daemon typically running on Linux servers, serving a role of a a "peer" in a Federation by communicating with other "peers" to form a consensus.
* Client side: [`fedimint-client`](./fedimint_client/index.html) library, that handles client side state handling and
communication with Fedimint peers. This library can be used to build Fedimint client applications that can run on
desktop computers, mobile devices and in web browsers (WASM).

More high level documentation is available as a part of [`fedimint-docs`](./fedimint_docs/index.html) crate.