#!/bin/bash
current_dir=$(pwd)
target_dir="/usr/local/include/pmacct"

source_dir=$1

echo "This script will clear $target_dir and move all .h files from $source_dir into it while preserving the tree structure"

while true; do
    read -p "Do you want to proceed? [Y/N] " yn
    case $yn in
        [Yy]* ) rm -rf $target_dir; rsync -a --include '*/' --include '*.h' --exclude '*' "$source_dir" "$target_dir" --prune-empty-dirs; echo "Done."; break;;
        [Nn]* ) echo "Aborted."; exit;;
        * ) echo "Please answer yes or no.";;
    esac
done

cd "$current_dir" || exit