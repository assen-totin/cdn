/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "utils.h"
#include "cache.h"

/**
 * File metadata from internal
 */
ngx_int_t transport_internal(session_t *session, metadata_t *metadata, ngx_http_request_t *r, int mode) {
	char *path, *key, *tmp;
	int file_fd, error;
	struct stat statbuf;
	btree_t *node = NULL;
	uint64_t h1, h2;

	// Set path to metadata file: original file name + ".meta"
	if ((path = ngx_pcalloc(r->pool, strlen(metadata->path) + 6)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata filename.", strlen(metadata->path) + 6);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	sprintf(path, "%s.meta", metadata->path);

	// Save, delete or read metadata
	if (mode == METADATA_INSERT) {
		// Save metadata to CDN meta file
		if ((file_fd = open(path, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP)) == -1) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Upload request: failed to create metadata file %s: %s", path, strerror(errno));
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		if (write(file_fd, (const void *)session->auth_request, strlen(session->auth_request)) < strlen(session->auth_request)) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Internal transport: failed to write %l bytes to metadata file %s: %s", strlen(session->auth_request), path, strerror(errno));
			close(file_fd);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		close(file_fd);
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
		if (ngx_http_cdn_cache->mem_max) {
			// Convert the 32-character file ID to 16-byte key
			tmp = malloc(17);
			strncpy(tmp, metadata->file, 16);
			h1 = strtoul(tmp, NULL, 16);
			strncpy(tmp, metadata->file + 16, 16);
			h2 = strtoul(tmp, NULL, 16);
			free(tmp);
			key = malloc(16);
			memcpy(key, &h1, 8);
			memcpy(key + 8, &h2, 8);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Internal transport: file %s: searching cache with key: %016xL%016xL", path, *((uint64_t*)key), *((uint64_t*)(key+8)));

			// Seek the key (motex-protected operation)
			// If key was found, res->left will have the value (NULL-terminated string); cast it to char*
			// If key was not found, it was added; store the value by passing the same res and the value (NULL-terminated char*) to cache_put()
			pthread_mutex_lock(&ngx_http_cdn_cache->lock);
			node = cache_seek(ngx_http_cdn_cache, key, &error);
			pthread_mutex_unlock(&ngx_http_cdn_cache->lock);

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
		if (ngx_http_cdn_cache->mem_max) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Internal transport: file %s: saving metadata in cache", path);
			cache_put(ngx_http_cdn_cache, node, strdup(session->auth_response));
		}

		close(file_fd);
	}

	return NGX_OK;
}

