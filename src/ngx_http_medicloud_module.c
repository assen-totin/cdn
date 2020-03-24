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
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Failed to allocate %l bytes for location config.", sizeof(ngx_http_medicloud_loc_conf_t));
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
	ngx_conf_merge_str_value(child->fs_depth, parent->fs_depth, FS_DEFAULT_DEPTH);
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
	ngx_table_elt_t **elts;
	medicloud_file_t *metadata;
	bson_t bc, bh;
	int i, j;
	char *s0, *s1, *s2;
	char *str1, *str2, *token, *subtoken, *saveptr1, *saveptr2;
	char *cookie_delim = " ", *cookie_subdelim = "=";
	char *cookie_name = NULL, *cookie_value = NULL;
	struct tm ltm;

	medicloud_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_medicloud_module);

	// Check if we should serve this request
	if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
		return NGX_DECLINED;
	}

	// Prepare session management data
	session_t session;
	session.fs_depth = atoi(from_ngx_str(r->pool, medicloud_loc_conf->fs_depth));
	session.fs_root = from_ngx_str(r->pool, medicloud_loc_conf->fs_root);
	session.auth_socket = from_ngx_str(r->pool, medicloud_loc_conf->auth_socket);
	session.hdr_authorisation = NULL;
	session.hdr_if_none_match = NULL;
	session.hdr_if_modified_since = -1;

	// Set some defaults (to be used if no corresponding field is found)
	metadata = ngx_pcalloc(r->pool, sizeof(medicloud_file_t));
	if (metadata == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata.", sizeof(medicloud_file_t));
		return NGX_ERROR;
	}

	metadata->etag = NULL;
	metadata->file = NULL;
	metadata->filename = NULL;
	metadata->content_type = NULL;
	metadata->content_disposition = NULL;
	metadata->data = NULL;
	metadata->length = -1;
	metadata->upload_date = -1;
	metadata->status = -1;

	// Attach metadata to request for further use
	ngx_http_set_ctx(r, metadata, ngx_http_medicloud_module);

	// URI
	session.uri = from_ngx_str(r->pool, r->uri);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found URI: %s", session.uri);

	// Headers
	if (r->headers_in.authorization) {
		session.hdr_authorisation = from_ngx_str(r->pool, r->headers_in.authorization->value);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found header Authorization: %s", session.hdr_authorisation);
	}
	if (r->headers_in.if_modified_since) {
		s1 = from_ngx_str(r->pool, r->headers_in.if_modified_since->value);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found header If-Modified-Since: %s", s1);

		if (strptime(s1, "%a, %d %b %Y %H:%M:%S", &ltm)) {
			session.hdr_if_modified_since = mktime(&ltm);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Converted value for header If-Modified-Since to timestamp: %l", session.hdr_if_modified_since);
		}
		else
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Failed to convert header If-Modified-Since to timestamp: %s", s1);
	}
	if (r->headers_in.if_none_match) {
		session.hdr_if_none_match = from_ngx_str(r->pool, r->headers_in.if_none_match->value);
		s1 = strchr(session.hdr_if_none_match, '"');
		s2 = strrchr(session.hdr_if_none_match, '"');
		if ((s1 == session.hdr_if_none_match) && (s2 == session.hdr_if_none_match + strlen(session.hdr_if_none_match) - 1)) {
			s0 = ngx_pcalloc(r->pool, strlen(session.hdr_if_none_match) - 1);
			if (s0 == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for hdr_if_none_match.", strlen(session.hdr_if_none_match) - 1);
				return NGX_ERROR;
			}

			strncpy(s0, session.hdr_if_none_match + 1, strlen(session.hdr_if_none_match) - 2);
			session.hdr_if_none_match = s0;
		}
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found header If-None-Match: %s", session.hdr_if_none_match);
	}

	// TODO: support Range incoming header
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range

	// Prepare outbound message to auth server in session->auth_req
	bson_t b = BSON_INITIALIZER;
	BSON_APPEND_UTF8 (&b, "uri", session.uri);

	// Append headers
	BSON_APPEND_DOCUMENT_BEGIN(&b, "headers", &bh);
	if (session.hdr_if_modified_since > 0)
		BSON_APPEND_INT32 (&bh, "if_modified_since", session.hdr_if_modified_since);
	if (session.hdr_if_none_match)
		BSON_APPEND_UTF8 (&bh, "if_none_match", session.hdr_if_none_match);
	if (session.hdr_authorisation)
		BSON_APPEND_UTF8 (&bh, "authorization", session.hdr_authorisation);
	bson_append_document_end (&b, &bh);

	// Append cookies
	BSON_APPEND_DOCUMENT_BEGIN(&b, "cookies", &bc);
	if (r->headers_in.cookies.nelts) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found a total of %l Cookie header", r->headers_in.cookies.nelts);
		elts = r->headers_in.cookies.elts;

		for (i=0; i<r->headers_in.cookies.nelts; i++) {
			s0 = from_ngx_str(r->pool, elts[i]->value);
			for (str1 = s0; ; str1 = NULL) {
				token = strtok_r(str1, cookie_delim, &saveptr1);
				if (token == NULL)
					break;

				s1 = strchr(token, ';');
				if (s1 == token + strlen(token) - 1) {
					s2 = ngx_pcalloc(r->pool, strlen(token));
					if (s2 == NULL) {
						ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for cookie token.", strlen(token));
						return NGX_ERROR;
					}
					strncpy(s2, token, strlen(token) - 1);
				}
				else
					s2 = token;

				for (j=0, str2 = s2; ; j++, str2 = NULL) {
					subtoken = strtok_r(str2, cookie_subdelim, &saveptr2);
					if (subtoken == NULL)
						break;

					if (j == 0) {
						cookie_name = ngx_pcalloc(r->pool, strlen(subtoken) + 1);
						if (cookie_name == NULL) {
							ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for cookie_name.", strlen(subtoken) + 1);
							return NGX_ERROR;
						}
						strcpy(cookie_name, subtoken);
					}
					else if (j == 1) {
						cookie_value = ngx_pcalloc(r->pool, strlen(subtoken) + 1);
						if (cookie_value == NULL) {
							ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for cookie_value.", strlen(subtoken) + 1);
							return NGX_ERROR;
						}
						strcpy(cookie_value, subtoken);
					}
					else
						ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Malformed cookie %s", s0);
				}

				if (j == 2) {
					BSON_APPEND_UTF8 (&bc, cookie_name, cookie_value);
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found cookie %s with value %s", cookie_name, cookie_value);
				}
			}
		}
	}
	else
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "No cookies found");

	bson_append_document_end (&b, &bc);

	session.auth_req = bson_as_json (&b, NULL);

	// Query for metadata here over the Unix socket
	ret = get_metadata(&session, r);
	bson_free(session.auth_req);
	if (ret)
		return ret;

	// Process metadata
	ret = process_metadata(&session, metadata, r);
	free(session.auth_resp);
	if (ret)
		return ret;

	// Process the file
	ret = read_fs(&session, metadata, r);
	if (ret)
		return ret;

	// Send the file
	ret = send_file(&session, metadata, r);

	// NB: The mapped file will be unmapped by the cleanup handler once data is sent to client

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
	if (session->auth_resp == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for auth_resp.", AUTH_BUFFER_CHUNK);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

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
					if (session->auth_resp == NULL) {
						ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to reallocate %l bytes for auth_resp.", auth_resp_len + AUTH_BUFFER_CHUNK);
						return NGX_HTTP_INTERNAL_SERVER_ERROR;
					}
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
ngx_int_t process_metadata(session_t *session, medicloud_file_t *metadata, ngx_http_request_t *r) {
	bson_t doc;
	bson_error_t error;
	bson_iter_t iter;
	const char *bson_key;
	const char *bson_val_char;

	// Walk around the JSON which we received from the authentication servier, session->auth_resp
	if (! bson_init_from_json(&doc, session->auth_resp, strlen(session->auth_resp), &error)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to parse JSON (%s): %s", error.message, session->auth_resp);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (! bson_iter_init (&iter, &doc)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to initialise BSON iterator");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	while(bson_iter_next(&iter)) {
		bson_key = bson_iter_key (&iter);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing metadata key %s with type %i", bson_key, bson_iter_type(&iter));

		if ((! strcmp(bson_key, "file")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			bson_val_char = bson_iter_utf8 (&iter, NULL);
			metadata->file = ngx_pcalloc(r->pool, strlen(bson_val_char) + 1);
			if (metadata->file == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata file.", strlen(bson_val_char) + 1);
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
			strcpy(metadata->file, bson_val_char);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata file: %s", metadata->file);
		}

		else if ((! strcmp(bson_key, "filename")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			bson_val_char = bson_iter_utf8 (&iter, NULL);
			metadata->filename = ngx_pcalloc(r->pool, strlen(bson_val_char) + 1);
			if (metadata->filename == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata filename.", strlen(bson_val_char) + 1);
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
			strcpy(metadata->filename, bson_val_char);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata filename: %s", metadata->filename);
		}

		else if ((! strcmp(bson_key, "error")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			bson_val_char = bson_iter_utf8 (&iter, NULL);
			if (strlen(bson_val_char)) {
				metadata->error = ngx_pcalloc(r->pool, strlen(bson_val_char) + 1);
				if (metadata->error == NULL) {
					ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata error.", strlen(bson_val_char) + 1);
					return NGX_HTTP_INTERNAL_SERVER_ERROR;
				}
				strcpy(metadata->error, bson_val_char);
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata error: %s", metadata->error);
			}
		}

		else if ((! strcmp(bson_key, "content_type")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			bson_val_char = bson_iter_utf8 (&iter, NULL);
			metadata->content_type = ngx_pcalloc(r->pool, strlen(bson_val_char) + 1);
			if (metadata->content_type == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata content_type", strlen(bson_val_char) + 1);
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
			strcpy(metadata->content_type, bson_val_char);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata content_type: %s", metadata->content_type);
		}

		else if ((! strcmp(bson_key, "content_disposition")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			bson_val_char = bson_iter_utf8 (&iter, NULL);
			metadata->content_disposition = ngx_pcalloc(r->pool, strlen(bson_val_char) + 1);
			if (metadata->content_disposition == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata content_disposition.", strlen(bson_val_char) + 1);
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
			strcpy(metadata->content_disposition, bson_val_char);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata content_disposition: %s", metadata->content_disposition);
		}

		else if ((! strcmp(bson_key, "etag")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			bson_val_char = bson_iter_utf8 (&iter, NULL);
			metadata->etag = ngx_pcalloc(r->pool, strlen(bson_val_char) + 1);
			if (metadata->etag == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata etag.", strlen(bson_val_char) + 1);
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
			strcpy(metadata->etag, bson_val_char);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata etag: %s", metadata->etag);
		}

		else if ((! strcmp(bson_key, "status")) && (bson_iter_type(&iter) == BSON_TYPE_INT32)) {
			metadata->status = bson_iter_int32 (&iter);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata status: %l", metadata->status);
		}

		else if (! strcmp(bson_key, "length")) {
			if (bson_iter_type(&iter) == BSON_TYPE_INT32)
				metadata->length = bson_iter_int32 (&iter);
			else if (bson_iter_type(&iter) == BSON_TYPE_INT64)
				metadata->length = bson_iter_int64 (&iter);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata length: %l", metadata->length);
		}

		else if ((! strcmp(bson_key, "upload_date")) && (bson_iter_type(&iter) == BSON_TYPE_DATE_TIME)) {
			metadata->upload_date = bson_iter_date_time (&iter) / 1000;
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata upload_date: %l", metadata->upload_date);
		}
	}

	// Check for error
	if ((metadata->status > 0) && (metadata->status != NGX_HTTP_OK)) {
		if (metadata->error)
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Auth service returned error: %s", metadata->error);
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Auth service returned status: %l", metadata->status);
		return metadata->status;
	}

	// Log an error if such was returned (with status 200 or no status)
	if (metadata->error)
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Auth service returned error: %s", metadata->error);

	// Check if we have the file name ro serve and returnerror if we don't have it
	if (! metadata->file) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Filename not received, aborting request.");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Check if we have the end user's file name and use the CDN filename if missing
	if (! metadata->filename) {
		metadata->filename = ngx_pcalloc(r->pool, strlen(metadata->file) + 1);
		if (metadata->filename == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata filename.", strlen(metadata->file) + 1);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		strcpy(metadata->filename, metadata->file);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s filename not found, will use file ID %s", metadata->file, metadata->file);
	}

	// Check if we have the content type and use the default one if missing
	if (! metadata->content_type) {
		metadata->content_type = ngx_pcalloc(r->pool, strlen(DEFAULT_CONTENT_TYPE) + 1);
		if (metadata->content_type == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata content_type.", strlen(DEFAULT_CONTENT_TYPE) + 1);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		strcpy(metadata->content_type, DEFAULT_CONTENT_TYPE);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s content_type not found, using default %s", metadata->file, DEFAULT_CONTENT_TYPE);
	}

	// Check if we have the content disposition and use the default one if missing
	if (! metadata->content_disposition)
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s content_disposition not found, not setting it", metadata->file);

	// Check if we have the eTag and use the default one if missing
	if (! metadata->etag) {
		metadata->etag = ngx_pcalloc(r->pool, strlen(DEFAULT_ETAG) + 1);
		if (metadata->etag == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata etag.", strlen(DEFAULT_ETAG) + 1);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		strcpy(metadata->etag, DEFAULT_ETAG);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s etag not found, using default %s", metadata->file, DEFAULT_ETAG);
	}

	// Check if we have the file length specified
	if (metadata->length < 0)
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s length not found, will use stat() to determine it", metadata->file);

	// Check if we have the upload date specified
	if (metadata->upload_date < 0)
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s upload_date not found, will use stat() to determine it", metadata->file);

	// Check if we have the HTTP response code and use the default one if missing
	if (metadata->status < 0) {
		metadata->status = DEFAULT_HTTP_CODE;
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s status not found, using default %s", metadata->file, DEFAULT_HTTP_CODE);
	}

	// Return 304 in certain cases
	if (session->hdr_if_none_match && metadata->etag && ! strcmp(session->hdr_if_none_match, metadata->etag))
		return NGX_HTTP_NOT_MODIFIED;

	// Return OK
	return (metadata->status == NGX_HTTP_OK) ? 0 : metadata->status;
}


/**
 * Read file from Filesystem
 */
ngx_int_t read_fs(session_t *session, medicloud_file_t *metadata, ngx_http_request_t *r) {
	// Get path
	int i, len, pos=0, fd;
	char *path;
	struct stat statbuf;
	ngx_http_cleanup_t *c;

	len = strlen(session->fs_root) + 1 + 2 * session->fs_depth + strlen(metadata->file) + 1;
	path = ngx_pcalloc(r->pool, len);
	if (path == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for path.", len);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	memset(path, '\0', len);

	memcpy(path, session->fs_root, strlen(session->fs_root));
	pos += strlen(session->fs_root);

	memcpy(path + pos, "/", 1);
	pos ++;

	for (i=0; i < session->fs_depth; i++) {
		memcpy(path + pos, metadata->file + i, 1);
		pos ++;
		memcpy(path + pos, "/", 1);
		pos ++;
	}

	memcpy(path + pos, metadata->file, strlen(metadata->file));

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s using path: %s", metadata->file, path);

	// Read the file: use mmap to map the physical file to memory
	if ((fd = open(path, O_RDONLY)) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s open() error %u", metadata->file, path, errno);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Fill-in any missing info from actual file
	if ((metadata->length < 0) || (metadata->upload_date < 0)) {
		fstat(fd, &statbuf);
		if (metadata->length < 0)
			metadata->length = statbuf.st_size;
		if (metadata->upload_date < 0)
			metadata->upload_date = statbuf.st_mtime;
	}

	if (session->hdr_if_modified_since >= metadata->upload_date) {
		if (close(fd) < 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s close() error %u", metadata->file, path, errno);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		return NGX_HTTP_NOT_MODIFIED;
	}

	// Map the physical file to memory
	if ((metadata->data = mmap(NULL, metadata->length, PROT_READ, MAP_SHARED, fd, 0)) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s mmap() error %u", metadata->file, path, errno);
		if (close(fd) < 0)
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s close() error %u", metadata->file, path, errno);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Set cleanup handler to unmap the file
	c = ngx_pcalloc(r->pool, sizeof(ngx_http_cleanup_t));
	if (c == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for cleanup.", sizeof(ngx_http_cleanup_t));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	c->handler = ngx_http_medicloud_cleanup;
	c->data = r;
	r->cleanup = c;

	if (close(fd) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s close() error %u", metadata->file, path, errno);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	return 0;
}

/**
 * Send file to client
 */
ngx_int_t send_file(session_t *session, medicloud_file_t *metadata, ngx_http_request_t *r) {
	int b1_len, b2_len;
	char *encoded = NULL;
	bool curl_encoded = false;
	CURL *curl;
    ngx_buf_t *b;
    ngx_chain_t *out;

	// ----- PREPARE THE HEADERS ----- //

	// HTTP status
	r->headers_out.status = NGX_HTTP_OK;

	// Content-Length
	r->headers_out.content_length_n = metadata->length;

	// Content-Type 
	r->headers_out.content_type.len = strlen(metadata->content_type);
	r->headers_out.content_type.data = (u_char*)metadata->content_type;
	
	// Last-Modified
	r->headers_out.last_modified_time = metadata->upload_date;

	// ETag
	b1_len = strlen(metadata->etag) + 2;
	ngx_buf_t *b1 = ngx_create_temp_buf(r->pool, b1_len);
	b1->last = ngx_sprintf(b1->last, "\"%s\"", metadata->etag);

	r->headers_out.etag = ngx_list_push(&r->headers_out.headers);
	r->headers_out.etag->hash = 1;
	r->headers_out.etag->key.len = sizeof(HEADER_ETAG) - 1;
	r->headers_out.etag->key.data = (u_char*)HEADER_ETAG;
	r->headers_out.etag->value.len = b1_len;
	r->headers_out.etag->value.data = b1->start;

	// Attachment: if file will be an attachment
	if (metadata->content_disposition && strcmp(metadata->content_disposition, CONTENT_DISPOSITION_ATTACHMENT)) {
		// URI-encode the file name?
		curl = curl_easy_init();
		if (curl) {
			encoded = curl_easy_escape(curl, metadata->filename, strlen(metadata->filename));
			if (encoded) {
				curl_encoded = true;
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s using URI-encoded filename %s", metadata->file, encoded);
			}
			else {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s unable to URI-encode filename %s", metadata->file, metadata->filename);
				encoded = metadata->filename;
			}
		}
		else {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s unable to init curl for URI-encoding", metadata->file);
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

	// Prepare output chain
	out = ngx_alloc_chain_link(r->pool);
	if (out == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for buffer chain.", sizeof(ngx_chain_t));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Prepare output buffer
	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for respone buffer.", sizeof(ngx_buf_t));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Prepare output chain; hook the buffer
	out->buf = b;
	out->next = NULL; 

	// Set the buffer
	// TODO: partial response if Range request header was set
	b->pos = metadata->data;
	b->last = metadata->data + metadata->length;
	b->mmap = 1; 
	b->last_buf = 1; 

	// ----- SERVE CONTENT ----- //

	// Send headers
	ngx_http_send_header(r); 

	// Send the body, and return the status code of the output filter chain.
	ngx_int_t ret = ngx_http_output_filter(r, out);

	// ----- ADDITIONAL (TIME CONSUMING) TASKS AFTER SERVING THE CONTENT ----- //
	// Nothing so far

	return ret;
} 

/**
 * Cleanup (unmap mapped file after serving)
 */
static void ngx_http_medicloud_cleanup(void *a) {
    ngx_http_request_t *r = (ngx_http_request_t *)a;
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Running connection cleanup.");

    medicloud_file_t *metadata;
    metadata = ngx_http_get_module_ctx(r, ngx_http_medicloud_module);
    if (munmap(metadata->data, metadata->length) < 0)
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s munmap() error %u", metadata->file, errno);
}

/**
 * Helper: convert Nginx string to normal
 */
char *from_ngx_str(ngx_pool_t *pool, ngx_str_t ngx_str) {
		if (! ngx_str.len)
			return NULL;

		char *ret = ngx_pcalloc(pool, ngx_str.len + 1);
		if (ret == NULL) {
			ngx_log_error(NGX_LOG_EMERG, pool->log, 0, "Failed to allocate %l bytes in from_ngx_str().", ngx_str.len + 1);
			return NULL;
		}
		memcpy(ret, ngx_str.data, ngx_str.len);
		return ret;
}

