#!/bin/bash

# Create filesystem storage in current directory (using recursion)

DIRS="0 1 2 3 4 5 6 7 8 9 a b c d e f"
DEFAULT_DEPTH=4
DEFAULT_ROOT="/opt/cdn"
DEFAULT_USER=root
DEFAULT_GROUP=root

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
		--user )   
			shift
			ARG_USER=$1
			;;
		--group )   
			shift
			ARG_GROUP=$1
			;;
		* )   
			echo "Unknown argument $1."
			echo "Usage: $0 [--depth N] [--root /some/path] [--user some_username] [--group some_groupname]"
			echo "Default values: depth $DEFAULT_DEPTH, root $DEFAULT_ROOT, user root, group root"
			exit 1
			;;
	esac

	shift
done

[ x$ARG_DEPTH == 'x' ] && ARG_DEPTH=$DEFAULT_DEPTH
[ x$ARG_ROOT == 'x' ] && ARG_ROOT=$DEFAULT_ROOT
[ x$ARG_USER == 'x' ] && ARG_USER=$DEFAULT_USER
[ x$ARG_GROUP == 'x' ] && ARG_GROUP=$DEFAULT_GROUP

mkdir -p $ARG_ROOT
pushd $ARG_ROOT

echo "Building CDN tree in $ARG_ROOT with depth of $ARG_DEPTH. Please, wait - this will take some time..."

make_dirs 0

# Prepare the log dir
for INDEX in $(seq 1 $ARG_DEPTH) ; do
        LOG_DIR="${LOG_DIR}/_"
done
mkdir -p ${ARG_ROOT}${LOG_DIR}

popd

chown -R $ARG_USER:$ARG_GROUP $ARG_ROOT

echo "Done."

