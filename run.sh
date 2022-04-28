#!/bin/bash

cargo build --release
cargo run --bin dealer --release > dealer.log &
cargo run --bin player --release > player1.log &
cargo run --bin player --release > player2.log
echo "Running!"