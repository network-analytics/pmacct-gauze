#!/bin/bash
current_dir=$(pwd)

source_dir=$1
target_dir=$2

if [ -z "$1" ]
  then
    target_dir="/usr/local/include/pmacct"
fi


echo "This script will clear $target_dir and move all .h files from $source_dir into it while preserving the tree structure"

while true; do
    read -p "Do you want to proceed? [Y/N] " yn
    case $yn in
        # Clear the target dir to remove old headers: rm -rf $target_dir
        # Clone all header files from $source_dir to $target_dir:
        #   rsync -a --include '*/' --include '*.h' --exclude '*' "$source_dir" "$target_dir" --prune-empty-dirs
        [Yy]* ) rm -rf $target_dir; rsync -a --include '*/' --include '*.h' --exclude '*' "$source_dir" "$target_dir" --prune-empty-dirs; echo "Done."; break;;
        [Nn]* ) echo "Aborted."; exit;;
        * ) echo "Please answer yes or no.";;
    esac
done

cd "$current_dir" || exit