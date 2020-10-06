#!/bin/bash

set -eu

ls -1 ./part2/ | sort -V | while IFS= read -r i; do
  echo "$i"
  diff -u \
    <(7z -slt l ./part2/"$i" | awk '/Packed Size.*[0-9]/{print $4}') \
    <(env LOG=1 ./7z_solution.py ./part2/"$i" | awk '/pack_pos:/{print $2}')
done
