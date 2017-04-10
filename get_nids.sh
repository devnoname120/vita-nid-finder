#!/bin/bash

if [ "$#" -lt 1 ]; then
	echo -e "Usage:\n\t$0 directory"
	exit 1
fi

if [ -z "$VITASDK" ]; then
	echo -e "Error: VITASDK is not set."
	exit 1
fi

if [ ! -d "$1" ]; then
	echo "Error: directory not found!"
	exit 1
fi

for file in "$1"/*_0.bin
do
	parts=($(basename "$file" | sed -rn "s/0x[0-9A-Fa-f]+_(0x[0-9A-Fa-f]+)_(\w+)_0\.bin/\1 \2/p"))
	name=${parts[1]}
	addr=${parts[0]}

	vita-nid-finder-flow "$file" "$name" "$addr"
done
