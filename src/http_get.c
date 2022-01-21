/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "auth.h"
#include "filter.h"
#include "index.h"
#include "request.h"
#include "transport.h"
#include "utils.h"

// We need this here as a declaration only; it is defined in main header file which will resolve it at runtime.
ngx_module_t ngx_http_cdn_module;

/**
 * Cleanup (unmap mapped file after serving)
 */
static void cleanup(metadata_t *metadata, ngx_http_request_t *r) {
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Running connection cleanup.");
	
	if (metadata->data && (munmap(metadata->data, metadata->length) < 0))
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s munmap() error %s", metadata->file16, strerror(errno));
}

/**
 * Cleanup (unmap mapped file after serving)
 */
static void ngx_http_cdn_cleanup(void *a) {
	ngx_http_request_t *r = (ngx_http_request_t *)a;
	metadata_t *metadata = ngx_http_get_module_ctx(r, ngx_http_cdn_module);
	cleanup(metadata, r);
}

/**
 * Check metdata for errors
 */
static ngx_int_t metadata_check(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	int i;

	// Log an error if such was returned (with status 200 or no status)
	if (metadata->error)
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Auth service returned error: %s", metadata->error);

	// If we did not get status code, use the configured one - based on the HTTP method (separate authorisation matrices for GET/HEAD and DELETE)
	if (metadata->status < 0) {
		// Check if we had an auth value
		if (session->auth_value) {
			// Check if we got back a response
			if (session->auth_response_count) {
				metadata->status = (r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)) ? session->instance->matrix_dnld->auth_resp : session->instance->matrix_del->auth_resp;
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s auth response -status +auth_value +resp setting status %l.", metadata->file16, metadata->status);
			}
			else {
				metadata->status = (r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)) ? session->instance->matrix_dnld->auth_noresp : session->instance->matrix_del->auth_noresp;
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s auth response -status +auth_value -resp setting status %l.", metadata->file16, metadata->status);
			}
		}
		else {
			// Check if we got back a response
			if (session->auth_response_count) {
				metadata->status = (r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)) ? session->instance->matrix_dnld->noauth_resp : session->instance->matrix_del->noauth_resp;
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s auth response -status -auth_value +resp setting status %l.", metadata->file16, metadata->status);
			}
			else {
				metadata->status = (r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)) ? session->instance->matrix_dnld->noauth_noresp : session->instance->matrix_del->noauth_noresp;
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s auth response -status -auth_value -resp setting status %l.", metadata->file16, metadata->status);
			}
		}
	}

	// Check if authorisation denied the request
	if (metadata->status >= NGX_HTTP_BAD_REQUEST ) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Auth service returned status: %l", metadata->status);
		return metadata->status;
	}

	// Check if we have the eTag and use the default one if missing
	if (! metadata->etag) {
		if ((metadata->etag = ngx_pcalloc(r->pool, strlen(DEFAULT_ETAG) + 1)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata etag.", strlen(DEFAULT_ETAG) + 1);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		strcpy(metadata->etag, DEFAULT_ETAG);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s etag not found, using default %s", metadata->file16, DEFAULT_ETAG);
	}

	// Check on ranges (headers Range and If-Range)
	if (session->hdr_ranges_cnt) {
		// If If-Range was sent, check whether we should serve the whole file or just the requested ranges
		if (session->hdr_if_range_etag) {
			// If header contains a tag, check if our file has the same; if not, serve complete file by resetting ranges
			if (strcmp(session->hdr_if_range_etag, metadata->etag))
				session->hdr_ranges_cnt = 0;
		}
		else if (session->hdr_if_range_time) {
			// If header contains a timestamp, check if our file has the same; if not, serve complete file by resetting ranges
			if (session->hdr_if_range_time < metadata->upload_timestamp)
				session->hdr_ranges_cnt = 0;
		}

		// If having Range, check that we do not go beyond the end of the file
		for (i=0; i < session->hdr_ranges_cnt; i++) {
			if (session->hdr_ranges[i].end > metadata->length)
				return NGX_HTTP_RANGE_NOT_SATISFIABLE;
			if ((session->hdr_ranges[i].end < 0) && (session->hdr_ranges[i].start > metadata->length))
				return NGX_HTTP_RANGE_NOT_SATISFIABLE;
			if ((session->hdr_ranges[i].start < 0) && (session->hdr_ranges[i].end > metadata->length))
				return NGX_HTTP_RANGE_NOT_SATISFIABLE;
		}
	}

	// Check if we have the file name to serve and return error if we don't have it
	if (! metadata->file16) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Filename not received, aborting request.");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Check if we have the original file name and use the CDN filename if missing
	if (! metadata->filename) {
		if ((metadata->filename = ngx_pcalloc(r->pool, strlen(metadata->file) + 1)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata filename.", strlen(metadata->file) + 1);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		strcpy(metadata->filename, metadata->file);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s filename not found, will use file ID %s", metadata->file16, metadata->file);
	}

	// Check if we have the content type and use the default one if missing
	if (! metadata->content_type) {
		if ((metadata->content_type = ngx_pcalloc(r->pool, strlen(DEFAULT_CONTENT_TYPE) + 1)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata content_type.", strlen(DEFAULT_CONTENT_TYPE) + 1);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		strcpy(metadata->content_type, DEFAULT_CONTENT_TYPE);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s content_type not found, using default %s", metadata->file16, DEFAULT_CONTENT_TYPE);
	}

	// Check if we have the content disposition and use the default one if missing
	if (! metadata->content_disposition)
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s content_disposition not found, not setting it", metadata->file16);

	// Return 304 in certain cases
	if (! session->hdr_ranges_cnt) {
		if (session->hdr_if_none_match && ! strcmp(session->hdr_if_none_match, metadata->etag))
			metadata->status = NGX_HTTP_NOT_MODIFIED;

		if (session->hdr_if_modified_since >= metadata->upload_timestamp)
			metadata->status = NGX_HTTP_NOT_MODIFIED;
	}

	// Return OK
	return (metadata->status == NGX_HTTP_OK) ? 0 : metadata->status;
}


/**
 * Read file
 */
ngx_int_t read_fs(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	int fd;
	ngx_http_cleanup_t *c;

	// Read the file: use mmap to map the physical file to memory
	if ((fd = open(metadata->path, O_RDONLY)) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s open() error %s", metadata->file16, metadata->path, strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (r->method & (NGX_HTTP_GET)) {
		// Map the physical file to memory
		if ((metadata->data = mmap(NULL, metadata->length, PROT_READ, MAP_SHARED, fd, 0)) < 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s mmap() error %s", metadata->file16, metadata->path, strerror(errno));
			if (close(fd) < 0)
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s close() error %s", metadata->file16, metadata->path, strerror(errno));
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		// Set cleanup handler to unmap the file
		if ((c = ngx_pcalloc(r->pool, sizeof(ngx_http_cleanup_t))) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for cleanup.", sizeof(ngx_http_cleanup_t));
			return NGX_ERROR;
		}
		c->handler = ngx_http_cdn_cleanup;
		c->data = r;
		r->cleanup = c;
	}

	if (close(fd) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s close() error %s", metadata->file16, metadata->path, strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	return NGX_OK;
}

/**
 * Send file to client
 */
ngx_int_t send_file(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	int b1_len, b2_len, i;
	int64_t hdr_content_range_start, hdr_content_range_end;
	char *encoded = NULL;
	bool curl_encoded = false;
	ngx_buf_t *b, *b1, *b2;
	ngx_chain_t *out = NULL, *curr, *prev = NULL;
	ngx_table_elt_t *h;
	ngx_int_t ret;

	// HTTP status
	r->headers_out.status = (session->hdr_ranges_cnt) ? NGX_HTTP_PARTIAL_CONTENT : NGX_HTTP_OK;

	// Content-Length
	// NB: Nginx violates RFC 2616 and mandates the return of 0 in case of HEAD, otherwise the response never completes
	if (r->method & (NGX_HTTP_GET)) {
		if (session->hdr_ranges_cnt) {
			r->headers_out.content_length_n = 0;
			for (i=0; i < session->hdr_ranges_cnt; i++) {
				// NB: The range includes both the starting and ending byte! They are zero-indexed!
				if ((session->hdr_ranges[i].start > -1) && (session->hdr_ranges[i].end > -1)) {
					// Serve starting with byte M to byte N inclusive, so M + N + 1 bytes
					r->headers_out.content_length_n += session->hdr_ranges[i].end - session->hdr_ranges[i].start + 1;
					hdr_content_range_start = session->hdr_ranges[i].start;
					hdr_content_range_end = session->hdr_ranges[i].end;
				}
				else if (session->hdr_ranges[i].start > -1) {
					// Serve starting with byte M to EOF (which is at index length-1, so no need to add 1 back here)
					r->headers_out.content_length_n += metadata->length - session->hdr_ranges[i].start;
					hdr_content_range_start = session->hdr_ranges[i].start;
					hdr_content_range_end = metadata->length;
				}
				else if (session->hdr_ranges[i].end > -1) {
					// Serve last N bytes (which means start at length - bytes -1, so no need to add 1 back here)
					r->headers_out.content_length_n += session->hdr_ranges[i].end;
					hdr_content_range_start = metadata->length - session->hdr_ranges[i].start;
					hdr_content_range_end = metadata->length;
				}
			}
		}
		else
			r->headers_out.content_length_n = metadata->length;
	}
	else
		r->headers_out.content_length_n = 0;

	// Content-Type 
	r->headers_out.content_type.len = strlen(metadata->content_type);
	r->headers_out.content_type.data = (u_char*)metadata->content_type;
	
	// Last-Modified
	r->headers_out.last_modified_time = metadata->upload_timestamp;

	// ETag
	b1_len = strlen(metadata->etag) + 2;
	if ((b1 = ngx_create_temp_buf(r->pool, b1_len)) == NULL) { 
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate bufer for etag header.");
		return NGX_ERROR;
	}
	b1->last = ngx_sprintf(b1->last, "\"%s\"", metadata->etag);

	r->headers_out.etag = ngx_list_push(&r->headers_out.headers);
	r->headers_out.etag->hash = 1;
	r->headers_out.etag->key.len = sizeof(HEADER_ETAG) - 1;
	r->headers_out.etag->key.data = (u_char*)HEADER_ETAG;
	r->headers_out.etag->value.len = b1_len;
	r->headers_out.etag->value.data = b1->start;

	// Attachment: if file will be an attachment
	if (metadata->content_disposition && ! strcmp(metadata->content_disposition, CONTENT_DISPOSITION_ATTACHMENT)) {
		// Lazy init curl, if not done so
		if (! session->curl)
			session->curl = curl_easy_init();
	
		if (session->curl) {
			encoded = curl_easy_escape(session->curl, metadata->filename, strlen(metadata->filename));
			if (encoded) {
				curl_encoded = true;
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s using URI-encoded filename %s", metadata->file16, encoded);
			}
			else {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s unable to URI-encode filename %s", metadata->file16, metadata->filename);
				encoded = metadata->filename;
			}
		}
		else 
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s unable to init curl for URI-encoding", metadata->file16);

		// Add Content-Disposition header
		// headers['Content-Disposition'] = 'attachment; filename="' + encodeURIComponent(this.file.filename) + '";'
		// NB: It is not in the standard Nginx header table, so add it as custom header
		if ((h = ngx_list_push(&r->headers_out.headers)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to add new output header.");
			return NGX_ERROR;
		}
		h->hash = 1;

		ngx_str_set(&h->key, HEADER_CONTENT_DISPOSITION);

		b2_len = 23 + strlen(encoded);

		if ((b2 = ngx_create_temp_buf(r->pool, b2_len)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate buffer for Content-Disposition header.");
			return NGX_ERROR;
		}
		b2->last = ngx_sprintf(b2->last, "attachment; filename=\"%s\"", encoded);
		h->value.len = b2_len;
		h->value.data = b2->start;
	}

	// Clean up cURL - it might have been init'ed in transport_http, or just above, or never
	if (session->curl) {
		if (curl_encoded)
			curl_free(encoded);
		curl_easy_cleanup(session->curl);
	}

	// Accept-Ranges header
	r->headers_out.accept_ranges = ngx_list_push(&r->headers_out.headers);
	r->headers_out.accept_ranges->hash = 1;
	r->headers_out.accept_ranges->key.len = sizeof(HEADER_ACCEPT_RANGES) - 1;
	r->headers_out.accept_ranges->key.data = (u_char*)HEADER_ACCEPT_RANGES;
	r->headers_out.accept_ranges->value.len = sizeof("bytes") - 1;
	r->headers_out.accept_ranges->value.data = (u_char*)"bytes";

	// Content-Range header if Range header was specified in the request
	if (session->hdr_ranges_cnt) {
		r->headers_out.content_range = ngx_list_push(&r->headers_out.headers);
		r->headers_out.content_range->hash = 1;
		r->headers_out.content_range->key.len = sizeof(HEADER_CONTENT_RANGE) - 1;
		r->headers_out.content_range->key.data = (u_char*)HEADER_CONTENT_RANGE;

		if ((r->headers_out.content_range->value.data = ngx_pcalloc(r->pool, 72)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for hdr_content_range.", 72);
			return NGX_ERROR;
		}

		if (session->hdr_ranges_cnt == 1) {
			sprintf((char *)r->headers_out.content_range->value.data, "bytes %lu-%lu/%lu", hdr_content_range_start, hdr_content_range_end, metadata->length);
			r->headers_out.content_range->value.len = strlen((const char*)r->headers_out.content_range->value.data);
		}
		else {
			sprintf((char *)r->headers_out.content_range->value.data, "bytes */%lu", metadata->length);
			r->headers_out.content_range->value.len = strlen((const char*)r->headers_out.content_range->value.data);
		}
	}

	// Send headers
	ret = ngx_http_send_header(r);
	if (ret == NGX_ERROR || ret > NGX_OK)
		return ret;

	// Map the file we are going to serve in the body
	if (r->method & (NGX_HTTP_GET)) {
		// Output with or without Range header
		if (session->hdr_ranges_cnt) {
			for (i=0; i < session->hdr_ranges_cnt; i++) {
				// Prepare new output chain link
				if ((curr = ngx_alloc_chain_link(r->pool)) == NULL) {
					ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for buffer chain.", sizeof(ngx_chain_t));
					return NGX_HTTP_INTERNAL_SERVER_ERROR;
				}

				// Prepare new output buffer in the link
				if ((curr->buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t))) == NULL) {
					ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for respone buffer.", sizeof(ngx_buf_t));
					return NGX_HTTP_INTERNAL_SERVER_ERROR;
				}

				// Set the buffer
				if ((session->hdr_ranges[i].start > -1) && (session->hdr_ranges[i].end > -1)) {
					curr->buf->pos = metadata->data + session->hdr_ranges[i].start;
					curr->buf->last = metadata->data + session->hdr_ranges[i].end + 1;
				}
				else if (session->hdr_ranges[i].start > -1) {
					curr->buf->pos = metadata->data + session->hdr_ranges[i].start;
					curr->buf->last = metadata->data + metadata->length;
				}
				else if (session->hdr_ranges[i].end > -1) {
					curr->buf->pos = metadata->data + metadata->length - session->hdr_ranges[i].end;
					curr->buf->last = metadata->data + metadata->length;
				}

				// Set conditions
				curr->next = NULL;
				curr->buf->mmap = 1;

				// First link: save as beginning of the chain
				if (i == 0)
					out = curr;

				// Last link: mark buffer and set next to NULL
				if (i == (session->hdr_ranges_cnt -1 ))
					curr->buf->last_buf = 1; 

				// Any link but the first: link to the previuos one
				if (i > 0)
					prev->next = curr;

				// Remember link
				prev = curr;
			}
		}
		else {
			// Prepare output chain
			if ((out = ngx_alloc_chain_link(r->pool)) == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for buffer chain.", sizeof(ngx_chain_t));
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}

			// Prepare output buffer
			if ((b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t))) == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for respone buffer.", sizeof(ngx_buf_t));
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}

			// Prepare output chain; hook the buffer
			out->buf = b;
			out->next = NULL; 

			// Set the buffer
			b->pos = metadata->data;
			b->last = metadata->data + metadata->length;
			b->mmap = 1; 
			b->last_buf = 1; 
		}
	}

	// Send the body, and return the status code of the output filter chain
	if (r->method & (NGX_HTTP_GET))
		ret = ngx_http_output_filter(r, out);

	return ret;
} 


/**
 * GET, HEAD, DELETE Content handler
 */
ngx_int_t cdn_handler_get(ngx_http_request_t *r) {
	ngx_int_t ret = NGX_OK;
	metadata_t *metadata;
	session_t *session;
	char *s1, *s2, *p1, *p2, *p3, *str1, *str2, *str3;
	int l1, l2;
	struct tm ltm;
	hdr_range_t *hdr_ranges;

	// Init session
	if ((session = init_session(r)) == NULL)
		return NGX_ERROR;

	// Init metadata
	if ((metadata = init_metadata(r)) == NULL)
		return NGX_ERROR;

	// Attach metadata to request for further use
	ngx_http_set_ctx(r, metadata, ngx_http_cdn_module);

	// Reject DELETE in read-only mode
	if ((! strcmp(session->read_only, "yes")) && (r->method & (NGX_HTTP_DELETE)))
		return NGX_HTTP_BAD_REQUEST;

	// Get the URI and split into parts
	if ((ret = get_uri(session, metadata, r)) > 0)
		return ret;

	// Get path
	if ((ret = get_path(session, metadata, r)) > 0)
		return ret;

	// Get stat for the file (will return 404 if file was not found, or 500 on any other error)
	if ((ret = get_stat(metadata, r)) > 0) {
		// For 404, check if we there is a pack leader and try to use it
		if (ret == NGX_HTTP_NOT_FOUND) {
			if (metadata->ext) {
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s not found, but extensions exists: %s", metadata->file16, metadata->ext16);
				memset(metadata->file16 + strlen(metadata->file16) - strlen(metadata->ext16) -1, '\0', 1);
				memset(metadata->file + strlen(metadata->file) - strlen(metadata->ext) -1, '\0', 1);
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Trying instead leader %s (for %s)", metadata->file16, metadata->file);

				if ((ret = get_path(session, metadata, r)) > 0)
					return ret;

				if ((ret = get_stat(metadata, r)) > 0)
					return ret;
		    }
			else
				return NGX_HTTP_NOT_FOUND;
		}
		else
			return ret;
	}

	// Process header If-Modified-Since
	if (r->headers_in.if_modified_since) {
		s1 = from_ngx_str(r->pool, r->headers_in.if_modified_since->value);
		if (strptime(s1, "%a, %d %b %Y %H:%M:%S", &ltm)) {
			session->hdr_if_modified_since = mktime(&ltm) + session->instance->tm_gmtoff;
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Converted value for header If-Modified-Since to timestamp: %l", session->hdr_if_modified_since);
		}
		else
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to convert header If-Modified-Since to timestamp: %s", s1);
	}

	// Process header If-None-Match
	if (r->headers_in.if_none_match) {
		s1 = from_ngx_str(r->pool, r->headers_in.if_none_match->value);
		if ((session->hdr_if_none_match = trim_quotes(r, s1)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for if_none_match.", strlen(s1) - 1);
			return NGX_ERROR;
		}
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found header If-None-Match: %s", session->hdr_if_none_match);
	}

	// Process header If-Range
	if (r->headers_in.if_range) {
		s1 = from_ngx_str(r->pool, r->headers_in.if_range->value);

		// This header may either be time or etag
		if (strptime(s1, "%a, %d %b %Y %H:%M:%S", &ltm)) {
			session->hdr_if_range_time = mktime(&ltm) + session->instance->tm_gmtoff;
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Converted value for header If-Range to timestamp: %l", session->hdr_if_range_time);
		}
		else {
			if ((session->hdr_if_range_etag = trim_quotes(r, s1)) == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for if_range.", strlen(s1) - 1);
				return NGX_ERROR;
			}
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found header If-Range: %s", session->hdr_if_range_etag);
		}
	}

	// Process header Range
	if (r->headers_in.range) {
		session->hdr_range = from_ngx_str(r->pool, r->headers_in.range->value);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found Range header: %s", session->hdr_range);

		// Split by equal sign
		if (! (s1 = strchr(session->hdr_range, '=')))
			return NGX_HTTP_BAD_REQUEST;
		s1++;

		// Loop around entries (we should have at least one)
		do {
			// Prepare a slot for the new range (allocate memory and copy existing ones)
			if ((hdr_ranges = ngx_pcalloc(r->pool, (session->hdr_ranges_cnt + 1) * sizeof(hdr_range_t))) == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for hdr_ranges.", (session->hdr_ranges_cnt + 1) * sizeof(hdr_range_t));
				return NGX_ERROR;
			}
			if (session->hdr_ranges)
				memcpy(hdr_ranges, session->hdr_ranges, session->hdr_ranges_cnt * sizeof(hdr_range_t));

			// Find next comma and its offset (or use end of string)
			str1 = strchr(s1, ',');
			str2 = (str1) ? str1 : s1 + strlen(s1);
			l1 = str2 - s1;

			// Print the entry to a new string
			if ((p1 = ngx_pcalloc(r->pool, l1 + 1)) == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for hdr_range.", l1 + 1);
				return NGX_ERROR;
			}
			snprintf(p1, l1 + 1, "%s", s1);

			// Process the entry - split by dash
			s2 = p1;
			str3 = strchr(s2, '-');

			// Left side of the entry
			l2 = str3 - s2;
			if ((p2 = ngx_pcalloc(r->pool, l2 + 1)) == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for hdr_range.", l2 + 1);
				return NGX_ERROR;
			}
			snprintf(p2, l2 + 1, "%s", s2);
			hdr_ranges[session->hdr_ranges_cnt].start = get_trimmed_int(p2);

			// Right side
			s2 += l2 + 1;
			if ((p3 = ngx_pcalloc(r->pool, l1 - l2)) == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for hdr_range.", l1 - l2);
				return NGX_ERROR;
			}
			sprintf(p3, "%s", s2);
			hdr_ranges[session->hdr_ranges_cnt].end = get_trimmed_int(p3);

			// Move to next entry
			s1 += l1 + 1;

			// Increment range counter and save ranges
			session->hdr_ranges_cnt++;
			session->hdr_ranges = hdr_ranges;
		} while(str1);
	}

	// Extract all headers if requested
	if (! strcmp(session->all_headers, "yes")) {
		if ((ret = get_all_headers(session, r)) > 0)
			return ret;
	}

	// Extract all cookies if requested
	if (! strcmp(session->all_cookies, "yes")) {
		if ((ret = get_all_cookies(session, r)) > 0)
			return ret;
	}

	// Try to find an authorisation token
	if ((ret = get_auth_token(session, r)) > 0)
		return ret;

	if (session->auth_token) {
		// Extract authentication token to value
		if (! strcmp(session->auth_type, AUTH_TYPE_JWT)) {
			if ((ret = auth_jwt(session, r)) > 0)
				return ret;
		}
		else if (! strcmp(session->auth_type, AUTH_TYPE_SESSION)) {
			if ((ret = auth_session(session, r)) > 0)
				return ret;
		}

		// Apply filter to auth_value
		if ((ret = filter_auth_value(session, r)) > 0)
			return ret;
	}

	// Prepare request (as per the configured request type)
	if (! strcmp(session->request_type, REQUEST_TYPE_JSON))
		ret = request_get_json(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_MONGO))
		ret = request_get_mongo(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_MYSQL))
		ret = request_get_sql(session, metadata, r, METADATA_SELECT);
	else if (! strcmp(session->request_type, REQUEST_TYPE_ORACLE))
		ret = request_get_sql(session, metadata, r, METADATA_SELECT);
	else if (! strcmp(session->request_type, REQUEST_TYPE_POSTGRESQL))
		ret = request_get_sql(session, metadata, r, METADATA_SELECT);
	else if (! strcmp(session->request_type, REQUEST_TYPE_XML))
		ret = request_get_xml(session, metadata, r);

	if (ret)
		return ret;

	// Query for metadata based on transport
	if (! strcmp(session->transport_type, TRANSPORT_TYPE_HTTP))
		ret = transport_http(session, metadata, r, METADATA_SELECT);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_INTERNAL))
		ret = transport_internal(session, metadata, r, METADATA_SELECT);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_MONGO))
		ret = transport_mongo(session, metadata, r, METADATA_SELECT);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_MYSQL))
		ret = transport_mysql(session, r, METADATA_SELECT);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_ORACLE))
		ret = transport_oracle(session, r, METADATA_SELECT);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_POSTGRESQL))
		ret = transport_postgresql(session, r, METADATA_SELECT);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_REDIS))
		ret = transport_redis(session, metadata, r, METADATA_SELECT);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_TCP))
		ret = transport_socket(session, r, SOCKET_TYPE_TCP);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_UNIX))
		ret = transport_socket(session, r, SOCKET_TYPE_UNUX);

	// Clean up BSON if used
	if (session->auth_request) {
		// For JSON, clean always
		if (! strcmp(session->request_type, REQUEST_TYPE_JSON)) {
			bson_free(session->auth_request);
			session->auth_request = NULL;
		}
		// For Mongo, only clean if we are not deleteting the file; we'll re-use the request to delete the data
		if (! strcmp(session->request_type, REQUEST_TYPE_MONGO)) {
			if (! (r->method & NGX_HTTP_DELETE)) {
				bson_free(session->auth_request);
				session->auth_request = NULL;
			}
		}
	}

	if (ret)
		return ret;

	// Process response (as per the configured request type)
	if (! strcmp(session->request_type, REQUEST_TYPE_JSON))
		ret = response_get_json(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_MONGO)) {
		ret = response_get_json(session, metadata, r);
		if (session->auth_response) {
			bson_free(session->auth_response);
			session->auth_response = NULL;
		}
	}
	else if (! strcmp(session->request_type, REQUEST_TYPE_MYSQL))
		ret = response_get_mysql(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_ORACLE))
		ret = response_get_oracle(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_POSTGRESQL))
		ret = response_get_postgresql(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_XML))
		ret = response_get_xml(session, metadata, r);

	// Clean up auth reponse unless using transport Internal or Redis
	if (session->auth_response) {
		if ((strcmp(session->transport_type, TRANSPORT_TYPE_INTERNAL)) && (strcmp(session->transport_type, TRANSPORT_TYPE_REDIS)))
			free(session->auth_response);
	}

	if (ret)
		return ret;

	// Check metadata
	if ((ret = metadata_check(session, metadata, r)) > 0)
		return ret;

	// Method-specific file processing
	if (r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)) {
		// Process the file
		if ((ret = read_fs(session, metadata, r)) > 0)
			return ret;

		// Send the file
		if ((ret = send_file(session, metadata, r)) > 0) {
			cleanup(metadata, r);
			return ret;
		}
	}
	else if (r->method & (NGX_HTTP_DELETE)) {
		// Delete the file
		if (unlink(metadata->path) < 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s unlink() error %s", metadata->file16, metadata->path, strerror(errno));
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		// Write to index (protect by mutex) - but only log errors
		pthread_mutex_lock(&session->instance->index->lock);
		if ((ret = index_write(session, INDEX_ACTION_DELETE, metadata->file16)) > 0)
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to write file ID %s to index: %u", metadata->file16, strerror(ret));
		pthread_mutex_unlock(&session->instance->index->lock);

		// Delete metadata (only for some transport types)
		// FIXME: No DELETE for HTTP transport?
		// NB: we ignore errors here
		if (! strcmp(session->transport_type, TRANSPORT_TYPE_INTERNAL)) {
			// NB: Our JSON/XML request was already prepared above for the AUTH step
			ret = transport_internal(session, metadata, r, METADATA_DELETE);
		}
		else if (! strcmp(session->transport_type, TRANSPORT_TYPE_MONGO)) {
			// NB: Our MongoDB request was already prepared above for the AUTH step
			ret = transport_mongo(session, metadata, r, METADATA_DELETE);
			if (session->auth_request)
				bson_free(session->auth_request);
		}
		else if (! strcmp(session->transport_type, TRANSPORT_TYPE_MYSQL)) {
			// Switch query to DELETE one and rebuild it
			session->sql_query = session->sql_query2;
			ret = request_get_sql(session, metadata, r, METADATA_DELETE);
			ret = transport_mysql(session, r, METADATA_DELETE);
		}
		else if (! strcmp(session->transport_type, TRANSPORT_TYPE_ORACLE)) {
			// Switch query to DELETE one and rebuild it
			session->sql_query = session->sql_query2;
			ret = request_get_sql(session, metadata, r, METADATA_DELETE);
			ret = transport_oracle(session, r, METADATA_DELETE);
		}
		else if (! strcmp(session->transport_type, TRANSPORT_TYPE_POSTGRESQL)) {
			// Switch query to DELETE one and rebuild it
			session->sql_query = session->sql_query2;
			ret = request_get_sql(session, metadata, r, METADATA_DELETE);
			ret = transport_postgresql(session, r, METADATA_DELETE);
		}
		else if (! strcmp(session->transport_type, TRANSPORT_TYPE_REDIS)) {
			// NB: Our JSON/XML request was already prepared above for the AUTH step
			ret = transport_redis(session, metadata, r, METADATA_DELETE);
		}

		return NGX_HTTP_NO_CONTENT;
	}

	// NB: The mapped file will be unmapped by the cleanup handler once data is sent to client
	return NGX_OK;
}

