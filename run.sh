#!/bin/bash

if [[ ! -d "logs" ]]; then
    mkdir "logs"
fi

cargo build --release
cargo run --bin dealer --release > logs/dealer.log 2>&1 &
sleep 3
cargo run --bin player --release > logs/player1.log 2>&1 &
cargo run --bin player --release > logs/player2.log 2>&1 &
cargo run --bin player --release > logs/player3.log 2>&1 &
echo "Running!"
