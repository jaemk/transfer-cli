# transfer-cli [![Build Status](https://travis-ci.org/jaemk/transfer-cli.svg?branch=master)](https://travis-ci.org/jaemk/transfer-cli)

> command line client for the [`transfer`](https://github.com/jaemk/transfer) encrypted file transfer utility

## Installation

See [`releases`](https://github.com/jaemk/transfer-cli/releases)

Or build from source:
- (Linux only) `apt install libssl-dev`
- `cargo build --release`

Updates:
- Self update functionality (from `github` releases) is available behind `--features update`
- Binary [`releases`](https://github.com/jaemk/transfer-cli/releases) are compiled with the `update` feature
- `transfer self update`

## Usage

```bash
transfer upload <file>
...
transfer download <key>
```

