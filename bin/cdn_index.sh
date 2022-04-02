#!/bin/bash

# Clean up job for CDN index

CONFIG_ROOT="/etc/cdn/index.d"

# Go over config files (one per CDN instance)
CONFIG_FILES=$(ls $CONFIG_ROOT/*.conf 2>/dev/null)
for CONFIG_FILE in $CONFIG_FILES ; do
	# Souce the config file for the CDN instance; it will give us the instance's index settings
	source $CONFIG_FILE

	# Find our index path from the index prefix and the CDN filesystem root
	INDEX_PATH=$FS_ROOT
	for i in $(seq 1 $FS_DEPTH) ; do
		    POS=$(echo $INDEX_PREFIX | cut -c $i)
		    INDEX_PATH="$INDEX_PATH/$POS"
	done

	# Remove all files older than $KEEP days
	find $INDEX_PATH -type f -mtime +$KEEP | xargs rm -f
done

