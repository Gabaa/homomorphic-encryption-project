#!/bin/bash

cargo build --release

cargo run --bin dealer --release > dealer.log 2>/dev/null &
sleep 5

cargo run --bin player --release > player1.log 2>/dev/null &
cargo run --bin player --release > player2.log 2>/dev/null &
echo "Running!"
