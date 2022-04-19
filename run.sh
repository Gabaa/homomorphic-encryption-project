#!/bin/bash

mkdir logs

cargo build --release

cargo run --bin dealer --release > logs/dealer.log 2>/dev/null &
sleep 5

cargo run --bin player --release > logs/player1.log 2>/dev/null &
cargo run --bin player --release > logs/player2.log 2>/dev/null &
echo "Running!"
