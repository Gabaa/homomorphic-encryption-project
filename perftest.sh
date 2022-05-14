#!/bin/bash
set -e

chparams() {
    sed -i "s/params_[0-9]*degree()/params_$1degree()/g" src/bin/player.rs
    sed -i "s/params_[0-9]*degree()/params_$1degree()/g" src/bin/dealer.rs
}

for i in {3..11}; do
    n=$((2 ** i))
    echo "Running for N=$n"
    chparams "$n"

    ./run.sh

    echo "Press a button to continue, or Ctrl+C to stop..."
    read -n 1 ans
done
