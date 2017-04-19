#!/bin/bash

shopt -s nullglob

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


function folder_nids {
	for file in "$1"/*_0.bin
	do
		parts=($(basename "$file" | sed -rn "s/0x[0-9A-Fa-f]+_(0x[0-9A-Fa-f]+)_(\w+)_0\.bin/\1 \2/p"))
		name=${parts[1]}
		addr=${parts[0]}
		
		# Files with this kind of filename are user
		./vita-nid-finder -c "$file" "$name" "$addr"
	done

	for file in "$1"/*_seg0.bin
	do
		parts=($(basename "$file" | sed -rn "s/(\w+)_(0x[0-9A-Fa-f]+)_seg0.bin/\2 \1/p"))
		name=${parts[1]}
		addr=${parts[0]}
		
		# Files with this kind of filename are kernel
		./vita-nid-finder -c "$file" "$name" "$addr"
	done
}


for folder in "$@"
do
	folder_nids "$folder"
done

