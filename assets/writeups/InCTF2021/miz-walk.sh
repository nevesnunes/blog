#!/bin/bash

a=(h j k l)
for i in "${a[@]}"; do
  walk="$i"
  inscount=$(echo "$walk" | qemu-x86_64 -d in_asm ./miz 2>&1 | wc -l)
  echo "$inscount $walk"
  for j in "${a[@]}"; do
    walk="$i$j"
    inscount=$(echo "$walk" | qemu-x86_64 -d in_asm ./miz 2>&1 | wc -l)
    echo "$inscount $walk"
    for k in "${a[@]}"; do
      walk="$i$j$k"
      inscount=$(echo "$walk" | qemu-x86_64 -d in_asm ./miz 2>&1 | wc -l)
      echo "$inscount $walk"
    done
  done
done | sort
