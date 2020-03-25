#!/bin/bash

# Create filesystem storage in current directory (using recursion)

DIRS="0 1 2 3 4 5 6 7 8 9 a b c d e f"
DEFAULT_DEPTH=4
DEFAULT_ROOT="/opt/cdn"

# Make directories at current level
make_dirs() {
	local A=$1
	local B=$((A+1))

	if [ $B -le $ARG_DEPTH ] ; then
		for DIR in $DIRS ; do
			mkdir $DIR
			cd $DIR
			make_dirs $B
		done
	fi

	cd ..
}

# Check command-line arguments
while [ "$1" != "" ]; do
	case $1 in
		--depth )   
			shift
			ARG_DEPTH=$1
			;;
		--root )   
			shift
			ARG_ROOT=$1
			;;
		* )   
			echo "Unknown argument $1."
			echo "Usage: ./$0 [--depth N] [--root /some/path]"
			echo "Default values: depth $DEFAULT_DEPTH, root $DEFAULT_ROOT"
			exit 1
			;;
	esac

	shift
done

[ x$ARG_DEPTH == 'x' ] && ARG_DEPTH=$DEFAULT_DEPTH
[ x$ARG_ROOT == 'x' ] && ARG_ROOT=$DEFAULT_ROOT

mkdir -p $ARG_ROOT
pushd $ARG_ROOT

echo "Building CDN tree in $ARG_ROOT with depth of $ARG_DEPTH. Please, wait - this will take some time..."

make_dirs 0

echo "Done."

popd

