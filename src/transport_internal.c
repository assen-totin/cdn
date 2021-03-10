/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "utils.h"
#include "cache.h"

/**
 * Helper: get key from metadata
 */
char *get_key(metadata_t *metadata, ngx_http_request_t *r) {
	char *tmp, *key;
	uint64_t h1, h2;

	// Convert the 32-character file ID to 16-byte key
	tmp = malloc(17);
	if (! tmp) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Internal transport: failed to allocate %l bytes for key.", 17);
		return NULL;
	}

	strncpy(tmp, metadata->file, 16);
	h1 = strtoul(tmp, NULL, 16);
	strncpy(tmp, metadata->file + 16, 16);
	h2 = strtoul(tmp, NULL, 16);
	free(tmp);

	key = malloc(16);
	if (! key) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Internal transport: failed to allocate %l bytes for key.", 16);
		return NULL;
	}

	memcpy(key, &h1, 8);
	memcpy(key + 8, &h2, 8);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Internal transport: file %s: searching cache with key: %016xL%016xL", path, *((uint64_t*)key), *((uint64_t*)(key+8)));

	return key;
}

/**
 * File metadata from internal
 */
ngx_int_t transport_internal(session_t *session, metadata_t *metadata, ngx_http_request_t *r, int mode) {
	char *path, *key;
	int file_fd, error;
	struct stat statbuf;
	btree_t *node = NULL;

	// Set path to metadata file: original file name + ".meta"
	if ((path = ngx_pcalloc(r->pool, strlen(metadata->path) + 6)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata filename.", strlen(metadata->path) + 6);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	sprintf(path, "%s.meta", metadata->path);

	// Save, delete or read metadata
	if ((mode == METADATA_INSERT) || (mode == METADATA_UPDATE)) {
		// Save metadata to CDN meta file
		if ((file_fd = open(path, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP)) == -1) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Upload request: failed to create metadata file %s: %s", path, strerror(errno));
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		if (write(file_fd, (const void *)session->auth_request, strlen(session->auth_request)) < strlen(session->auth_request)) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Internal transport: failed to write %l bytes to metadata file %s: %s", strlen(session->auth_request), path, strerror(errno));
			close(file_fd);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		close(file_fd);

		// Purge the record from the cache if found there
		if ((mode == METADATA_REPLACE) && (cdn_globals->cache->mem_max)) {
			// Get the key
			if ((key = get_key(metadata, r)) == NULL)
				return NGX_HTTP_INTERNAL_SERVER_ERROR;

			pthread_mutex_lock(&cdn_globals->cache->lock);
			cache_remove (cdn_globals->cache, key);
			pthread_mutex_unlock(&cdn_globals->cache->lock);
		}			
	}

	else if (mode == METADATA_DELETE) {
		// Delete metadata file
		if (unlink(path) < 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Metadata file %s unlink() error %s", path, strerror(errno));
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	else {
		// Read metadata - first check memory cache if it is enabled
		if (cdn_globals->cache->mem_max) {
			if ((key = get_key(metadata, r)) == NULL)
				return NGX_HTTP_INTERNAL_SERVER_ERROR;

			// Seek the key (mutex-protected operation)
			// If key was found, res->left will have the value (NULL-terminated string); cast it to char*
			// If key was not found, it was added; store the value by passing the same res and the value (NULL-terminated char*) to cache_put()
			pthread_mutex_lock(&cdn_globals->cache->lock);
			node = cache_seek(cdn_globals->cache, key, &error);
			pthread_mutex_unlock(&cdn_globals->cache->lock);

			free(key);

			if (error) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Internal transport: failed to seek cache key (malloc failed)");
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}

			if (node->left) {
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Internal transport: file %s: found key in cache", path);
				session->auth_response = (char *)node->left;
				return NGX_OK;
			}
		}
		
		// Metadata was not found in the memory cache, so read it from disk
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Internal transport: file %s: key not found in cache", path);
		if ((file_fd = open(path, O_RDONLY)) == -1) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Internal transport: failed to open metadata file %s: %s", path, strerror(errno));
			return NGX_OK;
		}

		// Get file size
		fstat(file_fd, &statbuf);

		// Prepare buffer to read the file
		if ((session->auth_response = ngx_pcalloc(r->pool, statbuf.st_size + 1)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata filename.", statbuf.st_size + 1);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		if (read(file_fd, session->auth_response, statbuf.st_size) < statbuf.st_size) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Internal transport: failed to read %l bytes metadata file %s: %s", statbuf.st_size, path, strerror(errno));
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		// NULL-terminate what we just read
		session->auth_response[statbuf.st_size] = '\0';

		// Save the data to the cache if it is enabled
		if (cdn_globals->cache->mem_max) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Internal transport: file %s: saving metadata in cache", path);
			cache_put(cdn_globals->cache, node, strdup(session->auth_response));
		}

		close(file_fd);
	}

	return NGX_OK;
}

