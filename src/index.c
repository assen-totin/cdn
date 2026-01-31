/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "globals.h"
#include "utils.h"

// Init index
index_t *index_init() {
	index_t *index;

	if ((index = malloc(sizeof(index_t))) == NULL)
		return NULL;

	index->fd = 0;
	index->prefix = NULL;

	index->year = 0;
	index->month = 0;
	index->day = 0;
	index->hour = 0;

	return index;
}

// Open index
ngx_int_t index_open(session_t* session) {
	struct tm t;
	char filename[256], path[256];
	time_t lt;
	index_t *index;
	fs_t *fs;

	index = session->instance->index;
	fs = session->instance->fs;

	// Get the time in UTC
	lt = time(NULL);
	gmtime_r(&lt, &t);

	// Check if we need to update the index
	if ((index->hour != t.tm_hour) || (index->day != t.tm_mday) || (index->month != t.tm_mon) || (index->year != t.tm_year)) {
		// Save time
		index->hour = t.tm_hour;
		index->day = t.tm_mday;
		index->month = t.tm_mon;
		index->year = t.tm_year;

		// Close old index file if opened (ignore errors)
		if (index->fd > 0)
			close(index->fd);

		// FIXME Compose new index name and path
		/*
		NB: The index file will be written to by multiple threads - 
		but in Nginx module's globals are confined per-thread, so the mutex will not work.
		This results in a race condition when the second of two concurrent uploads may 
		overwrite the first one when the index file has just been rotated.
		In theory, (Nginx-provided) shared memory may be used to host the mutex, 
		but this is cumbersome and not particularly well documented.
		Attempts to be more strict in file writing (O_DIRECT or O_SYNC) may lead to index file corruption on NFS
		when multiple threads attempt to write to it at the same time.
		As a workaround, we add a thread-specific suffix to the name of the hourly index file
		(so we end up with multiple index files for a given hour) and then use an external cron job 
		to combine them to the actual hourly index file that will be read by the replicas.
		*/
		snprintf(&filename[0], 256, "%s%02u%02u%02u%02u#%u", index->prefix, index->year + 1900, index->month + 1, index->day, index->hour, ngx_log_tid);
		bzero(&path[0], 256);
		get_path0(fs->root, fs->depth, &filename[0], &path[0]);

		// Open new index file
		if ((index->fd = open(&path[0], O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP)) == -1)
			return errno;
	}

	return NGX_OK;
}

// Write to index
ngx_int_t index_write(session_t *session, int action, char* filename) {
	char line[256];
	ngx_int_t ret;
	index_t *index;

	index = session->instance->index;

	// Prepare line to write
	switch(action) {
		case INDEX_ACTION_INSERT:
			snprintf(&line[0], 256, "I\t%s\n", filename);
			break;
		case INDEX_ACTION_UPDATE:
			snprintf(&line[0], 256, "U\t%s\n", filename);
			break;
		case INDEX_ACTION_DELETE:
			snprintf(&line[0], 256, "D\t%s\n", filename);
			break;
	}

	// Lock the file for us only
	pthread_mutex_lock(&globals->lock_index);

	// Check if we need to open a new index file
	if ((ret = index_open(session)) > 0) {
		pthread_mutex_unlock(&globals->lock_index);
		return ret;
	}

	// Seek EOF
	if (lseek(index->fd, 0, SEEK_END) == -1) {
		pthread_mutex_unlock(&globals->lock_index);
		return errno;
	}

	// Write
	if (write(index->fd, &line[0], strlen(&line[0])) < strlen(&line[0])) {
		pthread_mutex_unlock(&globals->lock_index);
		return errno;
	}

	// Flush
	fsync(index->fd);

	pthread_mutex_unlock(&globals->lock_index);

	return NGX_OK;
}

// Destroy index
void index_destroy(index_t *index) {
	if (! index)
		return;

	close(index->fd);

	if (index->prefix)
		free(index->prefix);

	free(index);
}

