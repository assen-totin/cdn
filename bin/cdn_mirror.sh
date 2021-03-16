#!/bin/bash

# Mirroring job for CDN

CONFIG_ROOT="/etc/cdn/mirror.d"
SAVED_ROOT="/var/lib/cdn/mirror.d"

# Get the UTC down to an hour as it was an hour ago
UNIX_TIMESTAMP=$(date +%s)
((UNIX_TIMESTAMP=UNIX_TIMESTAMP-3600))

DATE=$(date -u -d @$UNIX_TIMESTAMP +"%Y %m %d %H")
CURR_YEAR=$(echo $DATE | awk '{print $1}')
CURR_MONTH=$(echo $DATE | awk '{print $2}')
CURR_DAY=$(echo $DATE | awk '{print $3}')
CURR_HOUR=$(echo $DATE | awk '{print $4}')

TSTAMP="$CURR_YEAR$CURR_MONTH$CURR_DAY$CURR_HOUR"

# Go over config files (one per CDN instance)
CONFIG_FILES=$(ls $CONFIG_ROOT/*.conf)
for CONFIG_FILE in $CONFIG_FILES ; do
	# Souce the config file for the CDN instance; it will give us the instance's index settings
	source $CONFIG_FILE

	# Check our save point (if any), else skip
	[ ! -e $SAVED_ROOT/$INSTANCE_NAME ] && continue
	source $SAVED_ROOT/$INSTANCE_NAME

	# Compare our save point to the current time and build indices to read
	SAVED_YEAR=$(echo $SAVEPOINT | cut -c 1 4)
	SAVED_MONTH=$(echo $SAVEPOINT | cut -c 5 6)
	SAVED_DAY=$(echo $SAVEPOINT | cut -c 7 8)
	SAVED_HOUR=$(echo $SAVEPOINT | cut -c 9 10)

	# Loop for years
	for YEAR in $(seq $SAVED_YEAR $CURR_YEAR) ; do
		if [ $CURR_YEAR -eq $SAVED_YEAR ] ; then
			START_MONTH=$SAVED_MONTH
			END_MONTH=$CURR_MONTH
		elif [ $YEAR -eq $SAVED_YEAR ] ; then
			START_MONTH=$SAVED_MONTH
			END_MONTH=12
		elif [ $YEAR -eq $CURR_YEAR ] ; then
			START_MONTH=1
			END_MONTH=$CURR_MONTH
		else
			START_MONTH=1
			END_MONTH=12
		fi

		# Loop for months
		for MONTH in $(seq $START_MONTH $END_MONTH) ; do
			if [ $START_MONTH -eq $END_MONTH ] ; then
				START_DAY=$SAVED_DAY
				END_DAY=$CURR_DAY
			elif [ $MONTH -eq $SAVED_MONTH ] ; then
				START_DAY=$SAVED_DAY
				END_DAY=31
			elif [ $MONTH -eq $CURR_MONTH ] ; then
				START_DAY=1
				END_DAY=$CURR_DAY
			else
				START_DAY=1
				END_DAY=31
			fi

			# Loop for days
			for DAY in $(seq $START_DAY $END_DAY) ; do
				if [ $START_DAY -eq $END_DAY ] ; then
					START_HOUR=$SAVED_HOUR
					END_HOUR=$CURR_HOUR
				elif [ $DAY -eq $SAVED_DAY ] ; then
					START_HOUR=$SAVED_HOUR
					END_HOUR=23
				elif [ $DAY -eq $CURR_DAY ] ; then
					START_HOUR=0
					END_HOUR=$CURR_HOUR
				else
					START_HOUR=0
					END_HOUR=23
				fi

				# Compose index name and read it
				[[ $MONTH -lt 10 ]] && MY_MONTH="0$MONTH" ||  MY_MONTH="$MONTH"
				[[ $DAY -lt 10 ]] && MY_DAY="0$DAY" ||  MY_DAY="$DAY"
				[[ $HOUR -lt 10 ]] && MY_HOUR="0$MY_HOUR" ||  MY_HOUR="$MY_HOUR"
				INDEX_NAME="$INDEX_PREFIX$YEAR$MY_MONTH$MY_DAY$MY_HOUR"
				curl -s -o /tmp/$INDEX_NAME $URL/$INDEX_NAME
				cat /tmp/$INDEX_NAME >> /tmp/$INSTANCE_NAME
				rm -f /tmp/$INDEX_NAME
			done
		done
	done

	# Save our save point
	echo "SAVEPOINT=$CURR_YEAR$CURR_MONTH$CURR_DAY$CURR_HOUR" > $SAVED_ROOT/$INSTANCE_NAME

	# Check parallelism
	[ $WORKERS -eq 0 ] && WORKERS=$(cat /proc/cpuinfo | grep processor | wc -l)

	# Process the downloaded log
	/tmp/$INSTANCE_NAME




	# Find our index path from the index prefix and the CDN filesystem root
	INDEX_PATH=$FS_ROOT
	for i in $(seq 1 $FS_DEPTH) ; do
		    POS=$(echo $INDEX_PREFIX | cut -c $i)
		    INDEX_PATH="$INDEX_PATH/$POS"
	done

	# List the index files for the CDN instance
	INDEX_FILES=$(ls $INDEX_PATH/$INDEX_PREFIX*)

	# Decide which to keep and which to delete
	for INDEX_FILE in $INDEX_FILES ; do
		FILE_TSTAMP=$(echo $INDEX_FILE | awk -F '/' '{print $NF}' | sed "s/$INDEX_PREFIX//")
		[ $FILE_TSTAMP -lt $TSTAMP ] && rm -f $INDEX_FILE
	done
done




