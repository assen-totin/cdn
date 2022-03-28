#!/bin/bash

# Clean up job for CDN index

CONFIG_ROOT="/etc/cdn/index.d"

# Go over config files (one per CDN instance)
CONFIG_FILES=$(ls $CONFIG_ROOT/*.conf 2>/dev/null)
for CONFIG_FILE in $CONFIG_FILES ; do
	# Souce the config file for the CDN instance; it will give us the instance's index settings
	source $CONFIG_FILE

	# Get the UTC down to an hour as it was $KEEP days ago
	UNIX_TIMESTAMP=$(date +%s)
	((UNIX_TIMESTAMP=UNIX_TIMESTAMP-$KEEP*86400))

	DATE=$(date -u -d @$UNIX_TIMESTAMP +"%Y %m %d %H")
	YEAR=$(echo $DATE | awk '{print $1}')
	MONTH=$(echo $DATE | awk '{print $2}')
	DAY=$(echo $DATE | awk '{print $3}')
	HOUR=$(echo $DATE | awk '{print $4}')

	TSTAMP="$YEAR$MONTH$DAY$HOUR"

	# Find our index path from the index prefix and the CDN filesystem root
	INDEX_PATH=$FS_ROOT
	for i in $(seq 1 $FS_DEPTH) ; do
		    POS=$(echo $INDEX_PREFIX | cut -c $i)
		    INDEX_PATH="$INDEX_PATH/$POS"
	done

	# List the index files for the CDN instance
	INDEX_FILES=$(ls $INDEX_PATH/$INDEX_PREFIX* 2>/dev/null)

	# Decide which to keep and which to delete
	for INDEX_FILE in $INDEX_FILES ; do
		FILE_TSTAMP=$(echo $INDEX_FILE | awk -F '/' '{print $NF}' | sed "s/$INDEX_PREFIX//")
		[ $FILE_TSTAMP -lt $TSTAMP ] && rm -f $INDEX_FILE
	done
done

