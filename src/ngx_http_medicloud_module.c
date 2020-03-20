/**
 * Nginx media serving module for Medicloud.
 *
 * @author: Assen Totin assen.totin@curaden.ch
 */

#include "ngx_http_medicloud_module.h"

/**
 * Create location configuration
 */
static void* ngx_http_medicloud_create_loc_conf(ngx_conf_t* cf) {
	ngx_http_medicloud_loc_conf_t* loc_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_medicloud_loc_conf_t));
	if (loc_conf == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Failed to allocate memory for Medicloud location config.");
		return NGX_CONF_ERROR;
	}

	return loc_conf;
}

/**
 * Merge location configuration
 */
static char* ngx_http_medicloud_merge_loc_conf(ngx_conf_t* cf, void* void_parent, void* void_child) {
	ngx_http_medicloud_loc_conf_t *parent = void_parent;
	ngx_http_medicloud_loc_conf_t *child = void_child;

	ngx_conf_merge_str_value(child->fs_root, parent->fs_root, FS_DEFAULT_ROOT);
	ngx_conf_merge_uint_value(child->fs_depth, parent->fs_depth, FS_DEFAULT_DEPTH);
	ngx_conf_merge_str_value(child->auth_socket, parent->auth_socket, AUTH_DEFAULT_SOCKET);

	return NGX_CONF_OK;
}

/**
 * Init module and set handler
 */
static char *ngx_http_medicloud_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_medicloud_handler;

    return NGX_CONF_OK;
}

/**
 * Content handler
 */
static ngx_int_t ngx_http_medicloud_handler(ngx_http_request_t *r) {
	ngx_http_medicloud_loc_conf_t *medicloud_loc_conf;
	ngx_int_t ret;
	medicloud_file_t meta_file;

	medicloud_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_medicloud_module);

	// Prepare session management data
	session_t session;
	session.id = NULL;
	session.fs_depth = medicloud_loc_conf->fs_depth;
	session.fs_root = from_ngx_str(r->pool, medicloud_loc_conf->fs_root);
	session.auth_socket = from_ngx_str(r->pool, medicloud_loc_conf->auth_socket);
	session.hdr_authorisation = NULL;
	session.hdr_cookies = NULL;
	session.hdr_if_none_match = NULL;
	session.hdr_if_modified_since = NULL;
	session.if_modified_since = -1;

	// Set some defaults (to be used if no corresponding field is found)
	meta_file.etag = NULL;
	meta_file.filename = NULL;
	meta_file.content_type = NULL;
	meta_file.content_disposition = NULL;
	meta_file.data = NULL;
	meta_file.length = -1;
	meta_file.upload_date = -1;
	meta_file.status = -1;

	// URI
	session.uri = from_ngx_str(r->pool, r->uri);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found URI: %s", session.uri);

	// Headers
	if (r->headers_in.authorization) {
		session.hdr_authorisation = from_ngx_str(r->pool, r->headers_in.authorization->value);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found header Authorization: %s", session.hdr_authorisation);
	}
	if (r->headers_in.cookies) {
		session.hdr_cookies = from_ngx_str(r->pool, r->headers_in.cookies->value);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found header Cookies: %s", session.hdr_cookies);
	}
	if (r->headers_in.if_modified_since) {
		session.hdr_if_modified_since = from_ngx_str(r->pool, r->headers_in.if_modified_since->value);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found header If-Modified-Since: %s", session.hdr_if_modified_since);

		struct tm ltm;
		if (strptime(session.hdr_if_modified_since, "%a, %d %m %y %H:%M:%S GMT", &ltm))
			session.if_modified_since = mktime(&ltm);
	}
	if (r->headers_in.if_none_match) {
		session.hdr_if_none_match = from_ngx_str(r->pool, r->headers_in.if_none_match->value);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found header If-None-Match: %s", session.hdr_if_none_match);
	}

	// TODO: support Range incoming header
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range

	// Prepare outbound message to auth server in session->auth_req
	bson_t b = BSON_INITIALIZER;
	BSON_APPEND_UTF8 (&b, "uri", session.uri);

	bson_t bh;
	BSON_APPEND_DOCUMENT_BEGIN(&b, "headers", &bh);
	if (session.hdr_if_modified_since)
		BSON_APPEND_UTF8 (&bh, "if_modified_since", session.hdr_if_modified_since);
	if (session.hdr_if_none_match)
		BSON_APPEND_UTF8 (&bh, "if_none_match", session.hdr_if_none_match);
	if (session.hdr_authorisation)
		BSON_APPEND_UTF8 (&bh, "authorisation", session.hdr_authorisation);
	bson_append_document_end (&b, &bh);

	session.auth_req = bson_as_json (&b, NULL);

	// Query for metadata here over the Unix socket
	ret = get_metadata(&session, r);
	bson_free(session.auth_req);
	if (ret)
		return ret;

	// Process metadata
	ret = process_metadata(&session, &meta_file, r);
	free(session.auth_resp);
	if (ret)
		return ret;

	// Process the file
	ret = read_fs(&session, &meta_file, r);
	if (ret)
		return ret;

	// Send the file
	ret = send_file(&session, &meta_file, r);

	// Unmap memory mapped for sending the file
	if (munmap(meta_file.data, meta_file.length) < 0)
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s munmap() error %u", session.id, errno);

	return NGX_OK;
}


/**
 * Get file metadata
 */
ngx_int_t get_metadata(session_t *session, ngx_http_request_t *r) {
	// Socket variables
	struct sockaddr_un remote_un;
	int unix_socket, addr_len_un, bytes_in, auth_resp_len, auth_resp_pos;
	char msg_in[AUTH_BUFFER_CHUNK];

	// Init the Unix socket
	if ((unix_socket = socket(AF_UNIX, AUTH_SOCKET_TYPE, 0)) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to create socket: %s", strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Zero the structure, set socket type and path
	memset(&remote_un, '\0', sizeof(struct sockaddr_un));
	remote_un.sun_family = AF_UNIX;						
	strcpy(remote_un.sun_path, session->auth_socket);
	addr_len_un = strlen(remote_un.sun_path) + sizeof(remote_un.sun_family);

	// Connect to the authorisation service
	if (connect(unix_socket, (struct sockaddr *)&remote_un, addr_len_un) == -1) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to connect to Unix socket %s: %s", session->auth_socket, strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Send the message over the socket
	if (send(unix_socket, session->auth_req, strlen(session->auth_req), 0) == -1) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to write to Unix socket %s: %s", session->auth_socket, strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Signal we are done
	shutdown(unix_socket, SHUT_WR);

	// Await reponse
	auth_resp_pos = 0;
	session->auth_resp = malloc(AUTH_BUFFER_CHUNK);
	auth_resp_len = AUTH_BUFFER_CHUNK;
	memset(session->auth_resp, '\0', auth_resp_len);

	memset(&msg_in[0], '\0', sizeof(msg_in));

	while(1) {
		// Blocking read till we get a response
		if ((bytes_in = read(unix_socket, &msg_in[0], sizeof(msg_in)-1)) == -1) {
			free(session->auth_resp);
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to read from Unix socket %s: %s", session->auth_socket, strerror(errno));
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		else {
			printf("Received %u bytes over Unix socket\n", bytes_in);
			if (bytes_in) {
				// We read some more data, append it  (but expand buffer before that if necessary)
				if (auth_resp_pos + bytes_in > auth_resp_len - 1) {
					session->auth_resp = realloc(session->auth_resp, auth_resp_len + AUTH_BUFFER_CHUNK);
				}

				memcpy(session->auth_resp + auth_resp_pos, &msg_in[0], bytes_in);
				auth_resp_pos += bytes_in;
			}
			else {
				// NULL_terminate the incoming buffer and exit the loop
				memset(session->auth_resp + auth_resp_pos, '\0', 1);
				break;
			}
		}
	}

	// Clean up, log, return
	close(unix_socket);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Auth server response: %s", session->auth_resp);

	return 0;
}


/**
 * Process file metadata
 */
ngx_int_t process_metadata(session_t *session, medicloud_file_t *meta_file, ngx_http_request_t *r) {
	bson_t *doc;
	bson_error_t error;
	bson_iter_t iter;
	const char *bson_key;
	const char *bson_val_char;

	// Walk around the JSON which we received from the authentication servier, session->auth_resp
	if (! bson_init_from_json(doc, session->auth_resp, strlen(session->auth_resp), &error)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to parse JSON (%s): %s", error.message, session->auth_resp);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (! bson_iter_init (&iter, doc)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to initialise BSON iterator");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	while(bson_iter_next(&iter)) {
		bson_key = bson_iter_key (&iter);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing metadata key %s with type %i", bson_key, bson_iter_type(&iter));

		if ((! strcmp(bson_key, "filename")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			bson_val_char = bson_iter_utf8 (&iter, NULL);
			meta_file->filename = ngx_pcalloc(r->pool, strlen(bson_val_char) + 1);
			strcpy(meta_file->filename, bson_val_char);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s metadata filename: %s", session->id, meta_file->filename);
		}

		else if ((! strcmp(bson_key, "error")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			bson_val_char = bson_iter_utf8 (&iter, NULL);
			if (strlen(bson_val_char)) {
				meta_file->error = ngx_pcalloc(r->pool, strlen(bson_val_char) + 1);
				strcpy(meta_file->error, bson_val_char);
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s metadata error: %s", session->id, meta_file->error);
			}
		}

		else if ((! strcmp(bson_key, "content_type")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			bson_val_char = bson_iter_utf8 (&iter, NULL);
			meta_file->content_type = ngx_pcalloc(r->pool, strlen(bson_val_char) + 1);
			strcpy(meta_file->content_type, bson_val_char);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s metadata content_type: %s", session->id, meta_file->content_type);
		}

		else if ((! strcmp(bson_key, "content_disposition")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			bson_val_char = bson_iter_utf8 (&iter, NULL);
			meta_file->content_disposition = ngx_pcalloc(r->pool, strlen(bson_val_char) + 1);
			strcpy(meta_file->content_disposition, bson_val_char);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s metadata content_disposition: %s", session->id, meta_file->content_disposition);
		}

		else if ((! strcmp(bson_key, "etag")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			bson_val_char = bson_iter_utf8 (&iter, NULL);
			meta_file->etag = ngx_pcalloc(r->pool, strlen(bson_val_char) + 1);
			strcpy(meta_file->etag, bson_val_char);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s metadata etag: %s", session->id, meta_file->etag);
		}

		else if ((! strcmp(bson_key, "status")) && (bson_iter_type(&iter) == BSON_TYPE_INT32)) {
			meta_file->status = bson_iter_int32 (&iter);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s metadata status: %u", session->id, meta_file->status);
		}

		else if (! strcmp(bson_key, "length")) {
			if (bson_iter_type(&iter) == BSON_TYPE_INT32)
				meta_file->length = bson_iter_int32 (&iter);
			else if (bson_iter_type(&iter) == BSON_TYPE_INT64)
				meta_file->length = bson_iter_int64 (&iter);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s metadata length: %l", session->id, meta_file->length);
		}

		else if ((! strcmp(bson_key, "upload_date")) && (bson_iter_type(&iter) == BSON_TYPE_DATE_TIME)) {
			meta_file->upload_date = bson_iter_date_time (&iter) / 1000;
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s metadata upload_date: %l", session->id, meta_file->upload_date);
		}
	}

	// Check if we have all the fields
	if (! meta_file->filename) {
		meta_file->filename = ngx_pcalloc(r->pool, strlen(session->id) + 1);
		strcpy(meta_file->filename, session->id);
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s filename not found, will use file ID %s", session->id, session->id);
	}

	if (! meta_file->content_type) {
		meta_file->content_type = ngx_pcalloc(r->pool, strlen(DEFAULT_CONTENT_TYPE) + 1);
		strcpy(meta_file->content_type, DEFAULT_CONTENT_TYPE);
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s content_type not found, using default %s", session->id, DEFAULT_CONTENT_TYPE);
	}

	if (! meta_file->content_disposition) {
		meta_file->content_disposition = ngx_pcalloc(r->pool, strlen(DEFAULT_CONTENT_TYPE) + 1);
		strcpy(meta_file->content_disposition, DEFAULT_CONTENT_TYPE);
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s content_disposition not found, not setting it", session->id);
	}

	if (! meta_file->etag) {
		meta_file->etag = ngx_pcalloc(r->pool, strlen(DEFAULT_ETAG) + 1);
		strcpy(meta_file->etag, DEFAULT_ETAG);
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s content_type not found, using default %s", session->id, DEFAULT_ETAG);
	}

	if (meta_file->length < 0)
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s length not found, will use stat() to determine it", session->id);

	if (meta_file->upload_date < 0)
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s upload_date not found, will use stat() to determine it", session->id);

	if (meta_file->status < 0) {
		meta_file->status = DEFAULT_HTTP_CODE;
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s status not found, using default %s", session->id, DEFAULT_HTTP_CODE);
	}

	return (meta_file->status == NGX_HTTP_OK) ? 0 : meta_file->status;
}


/**
 * Read file from Filesystem
 */
ngx_int_t read_fs(session_t *session, medicloud_file_t *meta_file, ngx_http_request_t *r) {
	// Get path
	int i, len, pos=0, fd;
	char *path;
	struct stat statbuf;

	len = strlen(session->fs_root) + 1 + 2 * session->fs_depth + strlen(session->id) + 1;
	path = ngx_pcalloc(r->pool, len);
	memset(path, '\0', len);

	memcpy(path, session->fs_root, strlen(session->fs_root));
	pos += strlen(session->fs_root);

	memcpy(path + pos, "/", 1);
	pos ++;

	for (i=0; i < session->fs_depth; i++) {
		memcpy(path + pos, session->id + i, 1);
		pos ++;
		memcpy(path + pos, "/", 1);
		pos ++;
	}

	memcpy(path + pos, session->id, strlen(session->id));

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s using path: %s", session->id, path);

	// Read the file: use mmap to map the physical file to memory
	if ((fd = open(path, O_RDONLY)) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s open() error %u", session->id, path, errno);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Fill-in any missing info from actual file
	if ((meta_file->length < 0) || (meta_file->upload_date < 0)) {
		fstat(fd, &statbuf);
		if (meta_file->length < 0)
			meta_file->length = statbuf.st_size;
		if (meta_file->upload_date < 0)
			meta_file->upload_date = statbuf.st_mtime;
	}

	if ((meta_file->data = mmap(NULL, meta_file->length, PROT_READ, MAP_SHARED, fd, 0)) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s mmap() error %u", session->id, path, errno);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (close(fd) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s close() error %u", session->id, path, errno);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Return 304 in certain cases
	if (session->if_none_match && meta_file->etag && ! strcmp(session->if_none_match, meta_file->etag))
		return NGX_HTTP_NOT_MODIFIED;
	if (session->if_modified_since == meta_file->upload_date)
		return NGX_HTTP_NOT_MODIFIED;

	return 0;
}

/**
 * Send file to client
 */
ngx_int_t send_file(session_t *session, medicloud_file_t *meta_file, ngx_http_request_t *r) {
	int b1_len, b2_len;
	char *encoded = NULL;
	bool curl_encoded = false;
	CURL *curl;
    ngx_buf_t *b;
    ngx_chain_t out;

	// ----- PREPARE THE HEADERS ----- //

	// HTTP status
	r->headers_out.status = NGX_HTTP_OK;

	// Content-Length
	r->headers_out.content_length_n = meta_file->length;

	// Content-Type 
	r->headers_out.content_type.len = strlen(meta_file->content_type);
	r->headers_out.content_type.data = (u_char*)meta_file->content_type;
	
	// Last-Modified
	r->headers_out.last_modified_time = meta_file->upload_date;

	// ETag
	b1_len = strlen(meta_file->etag) + 2;
	ngx_buf_t *b1 = ngx_create_temp_buf(r->pool, b1_len);
	b1->last = ngx_sprintf(b1->last, "\"%s\"", meta_file->etag);

	r->headers_out.etag = ngx_list_push(&r->headers_out.headers);
	r->headers_out.etag->hash = 1;
	r->headers_out.etag->key.len = sizeof(HEADER_ETAG) - 1;
	r->headers_out.etag->key.data = (u_char*)HEADER_ETAG;
	r->headers_out.etag->value.len = b1_len;
	r->headers_out.etag->value.data = b1->start;

	// Attachment: if file will be an attachment
	if (meta_file->content_disposition && strcmp(meta_file->content_disposition, CONTENT_DISPOSITION_ATTACHMENT)) {
		// URI-encode the file name?
		curl = curl_easy_init();
		if (curl) {
			encoded = curl_easy_escape(curl, meta_file->filename, strlen(meta_file->filename));
			if (encoded) {
				curl_encoded = true;
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s using URI-encoded filename %s", session->id, encoded);
			}
			else {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s unable to URI-encode filename %s", session->id, meta_file->filename);
				encoded = meta_file->filename;
			}
		}
		else {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s unable to init curl for URI-encoding", session->id);
		}

		// Add Content-Disposition header
		// NB: We reuse the low of an existing, but unused standard header
		//headers['Content-Disposition'] = 'attachment; filename="' + encodeURIComponent(this.file.filename) + '";'
		b2_len = 23 + strlen(encoded);
		ngx_buf_t *b2 = ngx_create_temp_buf(r->pool, b2_len);
		b2->last = ngx_sprintf(b2->last, "attachment; filename=\"%s\"", encoded);

		r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
		r->headers_out.www_authenticate->hash = 1;
		r->headers_out.www_authenticate->key.len = sizeof(HEADER_CONTENT_DISPOSITION) - 1;
		r->headers_out.www_authenticate->key.data = (u_char*)HEADER_CONTENT_DISPOSITION;
		r->headers_out.www_authenticate->value.len = b2_len;
		r->headers_out.www_authenticate->value.data = b2->start;

		if (curl) {
			if (curl_encoded)
				curl_free(encoded);
			curl_easy_cleanup(curl);
		}
	}

	//TODO: Return Content-Range header if Range header was specified in the request

/*
	//TODO: enable this block once Range inbond header is supported
	// Accept-ranges (not strictly necessary, but good to have)
	r->headers_out.accept_ranges = ngx_list_push(&r->headers_out.headers);
	r->headers_out.accept_ranges->hash = 1;
	r->headers_out.accept_ranges->key.len = sizeof(HEADER_ACCEPT_RANGES) - 1;
	r->headers_out.accept_ranges->key.data = (u_char*)HEADER_ACCEPT_RANGES;
	r->headers_out.accept_ranges->value.len = sizeof("none") - 1;
	r->headers_out.accept_ranges->value.data = (u_char*)"none";
*/
	// ----- PREPARE THE BODY ----- //

	// Prepare output buffer
	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate response buffer");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Prepare output chain; hook the buffer
	out.buf = b;
	out.next = NULL; 

	// Set the buffer
	// TODO: partial response if Range request header was set
	b->pos = meta_file->data;
	b->last = meta_file->data + meta_file->length;
	b->memory = 1; 
	b->last_buf = 1; 

	// ----- SERVE CONTENT ----- //

	// Send headers
	ngx_http_send_header(r); 

	// Send the body, and return the status code of the output filter chain.
	ngx_int_t ret =  ngx_http_output_filter(r, &out);

	// ----- ADDITIONAL (TIME CONSUMING) TASKS AFTER SERVING THE CONTENT ----- //
	// Nothing so far

	return ret;
} 

/**
 * Helper: convert Nginx string to normal
 */
char *from_ngx_str(ngx_pool_t *pool, ngx_str_t ngx_str) {
		if (! ngx_str.len)
			return NULL;

		char *ret = ngx_pcalloc(pool, ngx_str.len + 1);
		memcpy(ret, ngx_str.data, ngx_str.len);
		return ret;
}

