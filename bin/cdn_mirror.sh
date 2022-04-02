#!/bin/bash

# Mirroring job for CDN

CONFIG_ROOT="/etc/cdn/mirror.d"
SAVED_ROOT="/var/lib/cdn/mirror.d"

# Function to get the path of a file from its name
get_file_path() {
	FILE_PATH=$FS_ROOT
	for i in $(seq 1 $FS_DEPTH) ; do
		POS=$(echo $FILE_NAME | cut -c $i)
		FILE_PATH="$FILE_PATH/$POS"
	done
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

# Get the UTC down to an hour as it was an hour ago
NOW_TS=$(date +%s)
((NOW_TS=NOW_TS-3600))

END_DATE=$(date -u -d @$NOW_TS +"%Y %m %d %H")
END_YEAR=$(echo $END_DATE | awk '{print $1}')
END_MONTH=$(echo $END_DATE | awk '{print $2}')
END_DAY=$(echo $END_DATE | awk '{print $3}')
END_HOUR=$(echo $END_DATE | awk '{print $4}')

END_TS=$(date -u -d "$END_YEAR-$END_MONTH-$END_DAY $END_HOUR:00:00" +%s)

# Go over config files (one per CDN instance)
CONFIG_FILES=$(ls $CONFIG_ROOT/*.conf)
for CONFIG_FILE in $CONFIG_FILES ; do
	# Souce the config file for the CDN instance; it will give us the instance's index settings
	source $CONFIG_FILE

	# Compare our save point to the current time and build indices to read
	if [ -e $SAVED_ROOT/$INSTANCE_NAME ] ; then
		source $SAVED_ROOT/$INSTANCE_NAME

		BEGIN_YEAR=$(echo $SAVEPOINT | cut -c 1-4)
		BEGIN_MONTH=$(echo $SAVEPOINT | cut -c 5-6)
		BEGIN_DAY=$(echo $SAVEPOINT | cut -c 7-8)
		BEGIN_HOUR=$(echo $SAVEPOINT | cut -c 9-10)

		BEGIN_TS=$(date -u -d "$BEGIN_YEAR-$BEGIN_MONTH-$BEGIN_DAY $BEGIN_HOUR:00:00" +%s)
		((BEGIN_TS=BEGIN_TS+3600))

		# Check if we've been here before
		[ $BEGIN_TS -gt $END_TS ] && continue
	else
		echo "SAVEPOINT=$END_YEAR$END_MONTH$END_DAY$END_HOUR" > $SAVED_ROOT/$INSTANCE_NAME
		continue
	fi

	# Loop over time periods
	for CURR_TS in $(seq $BEGIN_TS 3600 $END_TS) ; do
		CURR_DATE=$(date -u -d @$CURR_TS +"%Y %m %d %H")
		CURR_YEAR=$(echo $CURR_DATE | awk '{print $1}')
		CURR_MONTH=$(echo $CURR_DATE | awk '{print $2}')
		CURR_DAY=$(echo $CURR_DATE | awk '{print $3}')
		CURR_HOUR=$(echo $CURR_DATE | awk '{print $4}')

		INDEX_NAME="$INDEX_PREFIX$CURR_YEAR$CURR_MONTH$CURR_DAY$CURR_HOUR"
		CURL_URL="$URL/$INDEX_NAME"
		HTTP_CODE=$(curl -w %{http_code} -f -s -o /tmp/$INDEX_NAME $CURL_URL)
		RES=$?
		check_curl_error
		[ -f /tmp/$INDEX_NAME ] && cat /tmp/$INDEX_NAME >> /tmp/$INSTANCE_NAME
		rm -f /tmp/$INDEX_NAME
	done

	if [ -f /tmp/$INSTANCE_NAME ] ; then
		# Process the log file: inserts
		for FILE_NAME in $(cat /tmp/$INSTANCE_NAME | grep ^I | awk '{print $2}') ; do
			get_file_path
			CURL_URL="$URL/$FILE_NAME"
			HTTP_CODE=$(curl -w %{http_code} -f -s -o $FILE_PATH/$FILE_NAME $CURL_URL)
			RES=$?
			check_curl_error
		done

		# Process the log file: updates
		for FILE_NAME in $(cat /tmp/$INSTANCE_NAME | grep ^U | awk '{print $2}') ; do
			get_file_path
			CURL_URL="$URL/$FILE_NAME"
			HTTP_CODE=$(curl -w %{http_code} -f -s -o $FILE_PATH/$FILE_NAME $CURL_URL)
			RES=$?
			check_curl_error
		done

		# Process the log file: deletes
		for FILE_NAME in $(cat /tmp/$INSTANCE_NAME | grep ^D | awk '{print $2}') ; do
			get_file_path
			rm -f $FILE_PATH/$FILE_NAME
		done

		rm -f /tmp/$INSTANCE_NAME
	fi

	# Save our save point
	echo "SAVEPOINT=$END_YEAR$END_MONTH$END_DAY$END_HOUR" > $SAVED_ROOT/$INSTANCE_NAME
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

