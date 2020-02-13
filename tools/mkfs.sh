#!/bin/bash

# Create filesystem storage in current directory (using recursion)

DIRS="0 1 2 3 4 5 6 7 8 9 a b c d e f"
DEPTH=4

# Make directories at current level
make_dirs() {
	local A=$1
	local B=$((A+1))

	if [ $B -le $DEPTH ] ; then
		for DIR in $DIRS ; do
			mkdir $DIR
			cd $DIR
			make_dirs $B
		done
	fi

	cd ..
}

make_dirs 0

