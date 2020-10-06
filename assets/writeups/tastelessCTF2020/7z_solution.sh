#!/bin/sh

set -eux

rm -f 7z.png
ls -1 ./part2/ | sort -V | while IFS= read -r i; do
  ./7z_solution.py ./part2/"$i" >> 7z.png
done
