#!/bin/bash

# Mirroring job for CDN

MASTER_ROOT="/etc/cdn/mirror.d"
LOCAL_ROOT="/etc/cdn/index.d"
SAVED_ROOT="/var/lib/cdn/mirror.d"

# Helper to get the file path of a file from its name
# $1 is the file name
# $2 is the CDN depth
get_file_path() {
	FILE_PATH=""
	for i in $(seq 1 $2) ; do
		POS=$(echo $1 | cut -c $i)
		FILE_PATH="$FILE_PATH/$POS"
	done
}


# Helper to get a file from master
# $1 is the file name to get
# $2 is the local path to write file
get_file() {
	get_file_path $1 $MASTER_FS_DEPTH
	SRC=$URL$FILE_PATH/$1

	REGEX='https?://.*'
	if [[ $URL =~ $REGEX ]] ; then
		# The URL parameter is a remote URL, so use cURL to fetch the file
		# Get the web path for the remote file
		HTTP_CODE=$(curl -w %{http_code} -f -s -o $2 $SRC)
		RES=$?

		# Check for errors
		# NB: We do not treat 404 as an error - a file may have been added and then deleted prior to replication
		if [ $RES -gt 0 ] ; then
			# Curl exit code 22 is HTTP error 400+
			if [ $RES -ne 22 ] ; then
				_ERR=1
			elif [ $HTTP_CODE -ne 404 ] ; then
				_ERR=1
			fi

			if [ x$_ERR != 'x' ] ; then
				echo "Replication failed for $SRC curl code $RES HTTP code $HTTP_CODE"
				rm -f /tmp/$INSTANCE_NAME
				exit 1
			fi
		fi
	else
		# Local filesystem copy
		[ -f $SRC ] && cp -f $SRC $2
	fi
}

# Function to set file attributes
set_file_attributes() {
	if [ -f $1 ] ; then
		[ x$FS_USER != 'x' ] && [ x$FS_GROUP != 'x' ] && chown $FS_USER:$FS_GROUP $1
		[ x$FS_MODE != 'x' ] && chmod $FS_MODE $1
	fi
}

# Current timestamp and the name of the local transaction log for the current hour
NOW_TS=$(date +%s)
NOW_DATE=$(date -u -d @$NOW_TS +"%Y %m %d %H")
NOW_YEAR=$(echo $NOW_DATE | awk '{print $1}')
NOW_MONTH=$(echo $NOW_DATE | awk '{print $2}')
NOW_DAY=$(echo $NOW_DATE | awk '{print $3}')
NOW_HOUR=$(echo $NOW_DATE | awk '{print $4}')
BASE_LOG_NAME="$NOW_YEAR$NOW_MONTH$NOW_DAY$NOW_HOUR"

# Get the UTC down to an hour as it was an hour ago
((LAST_TS=NOW_TS-3600))
END_DATE=$(date -u -d @$LAST_TS +"%Y %m %d %H")
END_YEAR=$(echo $END_DATE | awk '{print $1}')
END_MONTH=$(echo $END_DATE | awk '{print $2}')
END_DAY=$(echo $END_DATE | awk '{print $3}')
END_HOUR=$(echo $END_DATE | awk '{print $4}')
END_TS=$(date -u -d "$END_YEAR-$END_MONTH-$END_DAY $END_HOUR:00:00" +%s)

# Go over config files (one per CDN instance)
MASTER_CONFIGS=$(ls $MASTER_ROOT/*.conf)
for MASTER_CONFIG in $MASTER_CONFIGS ; do
	# Souce the config file for the remote master CDN instance
	source $MASTER_CONFIG
	MASTER_INSTANCE_NAME=$(echo $MASTER_CONFIG | awk -F '/' '{print $NF}' |  awk -F '.' '{print $1}')

	# Source the local config file that receives the updates from this master
	LOCAL_CONFIG="$LOCAL_ROOT/$INSTANCE_NAME.conf"
	[ ! -e $LOCAL_CONFIG ] && continue
	source $LOCAL_CONFIG

	# Transaction log path and name
	LOG_NAME="$INDEX_PREFIX$BASE_LOG_NAME"
	get_file_path $LOG_NAME $FS_DEPTH
	TRANSACTION_LOG="$FS_ROOT/$FILE_PATH/$LOG_NAME"

	# Skip log (of DELETE operations on an append-only replica)
	# Place it in the same directory as transaction logs, but name it "skip.log"
	SKIP_LOG="$FILE_PATH/${INDEX_PREFIX}skip.log"

	# Compare our save point to the current time and build indices to read
	if [ -e $SAVED_ROOT/$MASTER_INSTANCE_NAME ] ; then
		source $SAVED_ROOT/$MASTER_INSTANCE_NAME

		BEGIN_YEAR=$(echo $SAVEPOINT | cut -c 1-4)
		BEGIN_MONTH=$(echo $SAVEPOINT | cut -c 5-6)
		BEGIN_DAY=$(echo $SAVEPOINT | cut -c 7-8)
		BEGIN_HOUR=$(echo $SAVEPOINT | cut -c 9-10)

		BEGIN_TS=$(date -u -d "$BEGIN_YEAR-$BEGIN_MONTH-$BEGIN_DAY $BEGIN_HOUR:00:00" +%s)
		((BEGIN_TS=BEGIN_TS+3600))

		# Check if we've been here before
		[ $BEGIN_TS -gt $END_TS ] && continue
	else
		echo "SAVEPOINT=$END_YEAR$END_MONTH$END_DAY$END_HOUR" > $SAVED_ROOT/$MASTER_INSTANCE_NAME
		continue
	fi

	# Loop over time periods
	for CURR_TS in $(seq $BEGIN_TS 3600 $END_TS) ; do
		CURR_DATE=$(date -u -d @$CURR_TS +"%Y %m %d %H")
		CURR_YEAR=$(echo $CURR_DATE | awk '{print $1}')
		CURR_MONTH=$(echo $CURR_DATE | awk '{print $2}')
		CURR_DAY=$(echo $CURR_DATE | awk '{print $3}')
		CURR_HOUR=$(echo $CURR_DATE | awk '{print $4}')

		INDEX_NAME="$MASTER_INDEX_PREFIX$CURR_YEAR$CURR_MONTH$CURR_DAY$CURR_HOUR"
		get_file $INDEX_NAME /tmp/$INDEX_NAME
		[ -f /tmp/$INDEX_NAME ] && cat /tmp/$INDEX_NAME >> /tmp/$INSTANCE_NAME
		rm -f /tmp/$INDEX_NAME
	done

	[ ! -e /tmp/$INSTANCE_NAME ] && continue

	# Process the log file: inserts
	for FILE_NAME in $(cat /tmp/$INSTANCE_NAME | grep ^I | awk '{print $2}') ; do
		get_file_path $FILE_NAME $FS_DEPTH
		LOCAL_FILE="$FS_ROOT$FILE_PATH/$FILE_NAME"
		get_file $FILE_NAME $LOCAL_FILE
		set_file_attributes $LOCAL_FILE
		[ $INTERMEDIATE_MASTER -gt 0 ] && echo -e "I\t$FILE_NAME" >> $TRANSACTION_LOG
	done

	# Process the log file: updates
	for FILE_NAME in $(cat /tmp/$INSTANCE_NAME | grep ^U | awk '{print $2}') ; do
		get_file_path $FILE_NAME $FS_DEPTH
		LOCAL_FILE="$FS_ROOT$FILE_PATH/$FILE_NAME"
		get_file $FILE_NAME $LOCAL_FILE
		set_file_attributes $LOCAL_FILE
		[ $INTERMEDIATE_MASTER -gt 0 ] && echo -e "U\t$FILE_NAME" >> $TRANSACTION_LOG
	done

	# Process the log file: deletes (if not an append-only replica)
	if [ $APPEND_ONLY -gt 0 ] ; then
		for FILE_NAME in $(cat /tmp/$INSTANCE_NAME | grep ^D | awk '{print $2}') ; do
			get_file_path $FILE_NAME $FS_DEPTH
			rm -f $FS_ROOT$FILE_PATH/$FILE_NAME
			[ $INTERMEDIATE_MASTER -gt 0 ] && echo -e "D\t$FILE_NAME" >> $TRANSACTION_LOG
		done
	else
		# Log the DELETE operation so that it may be carreid out later manually if desired
		# NB: Only apply to existing files (i.e. a file that was added and delete in the same transaction log will not be replicated at all)
		[ -f $FS_ROOT$FILE_PATH/$FILE_NAME ] && echo -e "D\t$FILE_NAME" >> $SKIP_LOG
	fi

	rm -f /tmp/$INSTANCE_NAME

	# Save our save point
	echo "SAVEPOINT=$END_YEAR$END_MONTH$END_DAY$END_HOUR" > $SAVED_ROOT/$MASTER_INSTANCE_NAME
done

## Check parallelism
#[ $WORKERS -eq 0 ] && WORKERS=$(cat /proc/cpuinfo | grep processor | wc -l)
#[ $WORKERS -gt 9 ] && WORKERS=9
#
## Prepare the downloaded log file (find unique entries and move deletes to be last)
#cat /tmp/$INSTANCE_NAME | sort -u -r > /tmp/$$
#mv -f /tmp/$$ /tmp/$INSTANCE_NAME
#
## Split the downloaded log into chunks
#pushd /tmp
#split -a 1 -n l/$WORKERS -d /tmp/$INSTANCE_NAME $INSTANCE_NAME
#popd

