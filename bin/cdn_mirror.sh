#!/bin/bash

# Mirroring job for CDN

MASTER_ROOT="/etc/cdn/mirror.d"
LOCAL_ROOT="/etc/cdn/index.d"
SAVED_ROOT="/var/lib/cdn/mirror.d"

# Function to get the path of a file from its name
get_file_path() {
	FILE_PATH=$FS_ROOT
	for i in $(seq 1 $FS_DEPTH) ; do
		POS=$(echo $1 | cut -c $i)
		FILE_PATH="$FILE_PATH/$POS"
	done
}

# Function to get the web path for an index file
get_web_path() {
        WEB_PATH=""
        for i in $(seq 1 $MASTER_FS_DEPTH) ; do
                POS=$(echo $1 | cut -c $i)
                WEB_PATH="$WEB_PATH/$POS"
        done
        WEB_PATH="$WEB_PATH/$1"
}

# Function to check for HTTP errors
check_curl_error() {
	if [ $RES -gt 0 ] ; then
		# Curl exit code 22 is HTTP error 400+
		if [ $RES -ne 22 ] ; then
			_ERR=1
		elif [ $HTTP_CODE -ne 404 ] ; then
			_ERR=1
		fi

		if [ x$_ERR != 'x' ] ; then
			echo "Replication failed for $CURL_URL curl code $RES HTTP code $HTTP_CODE"
			rm -f /tmp/$INSTANCE_NAME
			exit 1
		fi
	fi
}

# Function to set file attributes
set_file_attributes() {
	chown $FS_USER:$FS_GROUP $1
	chmod $FS_MODE $1
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
	get_file_path $LOG_NAME
	TRANSACTION_LOG="$FILE_PATH/$LOG_NAME"

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
		get_web_path $INDEX_NAME
		CURL_URL="$URL$WEB_PATH"
		HTTP_CODE=$(curl -w %{http_code} -f -s -o /tmp/$INDEX_NAME $CURL_URL)
		RES=$?
		check_curl_error
		[ -f /tmp/$INDEX_NAME ] && cat /tmp/$INDEX_NAME >> /tmp/$INSTANCE_NAME
		rm -f /tmp/$INDEX_NAME
	done

	[ ! -e /tmp/$INSTANCE_NAME ] && continue

	# Process the log file: inserts
	for FILE_NAME in $(cat /tmp/$INSTANCE_NAME | grep ^I | awk '{print $2}') ; do
		get_file_path $FILE_NAME
		get_web_path $FILE_NAME
		CURL_URL="$URL$WEB_PATH"
		HTTP_CODE=$(curl -w %{http_code} -f -s -o $FILE_PATH/$FILE_NAME $CURL_URL)
		RES=$?
		check_curl_error
		[ $HTTP_CODE -eq 200 ] && set_file_attributes $FILE_PATH/$FILE_NAME
		[ $INTERMEDIATE_MASTER -gt 0 ] && echo -e "I\t$FILE_NAME" >> $TRANSACTION_LOG
	done

	# Process the log file: updates
	for FILE_NAME in $(cat /tmp/$INSTANCE_NAME | grep ^U | awk '{print $2}') ; do
		get_file_path $FILE_NAME
		get_web_path $FILE_NAME
		CURL_URL="$URL$WEB_PATH"
		HTTP_CODE=$(curl -w %{http_code} -f -s -o $FILE_PATH/$FILE_NAME $CURL_URL)
		RES=$?
		check_curl_error
		[ $HTTP_CODE -eq 200 ] && set_file_attributes $FILE_PATH/$FILE_NAME
		[ $INTERMEDIATE_MASTER -gt 0 ] && echo -e "U\t$FILE_NAME" >> $TRANSACTION_LOG
	done

	# Process the log file: deletes (if not an append-only replica)
	if [ $APPEND_ONLY -gt 0 ] ; then
	for FILE_NAME in $(cat /tmp/$INSTANCE_NAME | grep ^D | awk '{print $2}') ; do
			get_file_path $FILE_NAME
			rm -f $FILE_PATH/$FILE_NAME
			[ $INTERMEDIATE_MASTER -gt 0 ] && echo -e "D\t$FILE_NAME" >> $TRANSACTION_LOG
		done
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

