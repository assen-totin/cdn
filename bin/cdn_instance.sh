#!/bin/bash

# Maintenance job for CDN instance

# This job should run early each hour, before the replicas pull the log for the preceding hour.
# Replica usually call the master at 5 minutes past the hour, so this should run, say, at 3 minutes past the hour
# (cron should not randomise run times)

CONFIG_ROOT="/etc/cdn/instance.d"

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

	# Go to the index directory
	cd $INDEX_PATH

	# Compose the name of the index file for the previous hour
	CURR_TS=$(date +%s)
	CURR_DT=$(date -d @${CURR_TS} -u +%Y%m%d%H)
	PREV_TS=$((CURR_TS-3600))
	PREV_DT=$(date -d @${PREV_TS} -u +%Y%m%d%H)
	FULL_LOG="${INDEX_PREFIX}${PREV_DT}"

	# Aggregate any partial transaction logs into an index file. 
	# File name format for a partial log is $INDEX_PREFIX + YYYYMMDDHH + "#" + PID
	# The full log file should be for the previous hour even if the partials are older,
	# this way the replicas will still find the changes.
	# Exclude any existing log for the current hour.
	for PARTIAL_LOG in $(find | grep '#' | grep -v $CURR_DT | awk -F '/' '{print $NF}') ; do
		cat $PARTIAL_LOG >> $FULL_LOG
		rm -f $PARTIAL_LOG
	done

	# Chown/chmod the file if configured
	[ "x$FS_USER" != 'x' ] && chown $FS_USER $FULL_LOG
	[ "x$FS_GROUP" != 'x' ] && chgrp $FS_GROUP $FULL_LOG
	[ "x$FS_MODE" != 'x' ] && chmod $FS_MODE $FULL_LOG

	# Cleanup: remove all files older than $KEEP days
	find -type f -mtime +$KEEP | xargs rm -f
done

