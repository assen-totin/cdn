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
	char *bson_tmp, *bucket, *attachment, *id;
	ngx_http_medicloud_loc_conf_t *medicloud_loc_conf;
	ngx_int_t ret;
	medicloud_file_t meta_file, dnld_file;

	medicloud_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_medicloud_module);

	// Prepare session management data
	session_t session;
	session.token = NULL;
	session.fs_depth = medicloud_loc_conf->fs_depth;
	session.fs_root = from_ngx_str(r->pool, medicloud_loc_conf->fs_root);
	session.auth_socket = from_ngx_str(r->pool, medicloud_loc_conf->auth_socket);

	// URI
	// URI format: /:bucket/download/:id
	// URI format: /:bucket/stream/:id
	session.uri = from_ngx_str(r->pool, r->uri);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found URI: %s", session.uri);

	session.uri_dup = from_ngx_str(r->pool, r->uri);

	// Get bucket
	bucket = strtok(session.uri_dup, "/");
	session.bucket = ngx_pnalloc(r->pool, strlen(bucket) + 1);
	strcpy(session.bucket, bucket);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found bucket: %s", session.bucket);

	// Check if we know anyhting about the bucket
	if ((! strcmp(session.bucket, LOCATION_PUBLIC1)) || (! strcmp(session.bucket, LOCATION_PUBLIC2))) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Bucket is public: %s", session.uri);
	}
	else if (!strcmp(session.bucket, LOCATION_PRIVATE)) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Bucket is private: %s", session.uri);
	}
	else {
		// Return code to refuse processing so that other filters may kick in
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "URI %s invalid bucket %s", session.uri, session.bucket);
		return NGX_DECLINED;
	}

	// Get attachment/stream mode
	attachment = strtok(NULL, "/");
	session.attachment = ngx_pnalloc(r->pool, strlen(attachment) + 1);
	strcpy(session.attachment, attachment);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found download/stream: %s", session.attachment);

	// Attachment flag based on URL
	if (!strcmp(attachment, DNLD_ATTACHMENT)) {
		session.is_attachment = true;
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Download will be an attachmanet");
	}
	else if (!strcmp(attachment, DNLD_STREAM)) {
		session.is_attachment = false;
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Download will be a stream");
	}
	else {
		// Return code to refuse processing so that other filters may kick in
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "URI %s invalid stream/download mode %s", session.uri, attachment);
		return NGX_DECLINED;
	}

	// Get media ID
	id = strtok(NULL, "/");
	if (! id) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "URI %s file ID not found", session.uri);
		return NGX_DECLINED;
	}
	session.id = ngx_pnalloc(r->pool, strlen(id) + 1);
	strcpy(session.id, id);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found file ID: %s", session.id);

	// Etag from client If-None-Match
	if (r->headers_in.if_none_match) {
		session.if_none_match = from_ngx_str(r->pool, r->headers_in.if_none_match->value);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Received ETag: %s", session.if_none_match);
	}
	else
		session.if_none_match = NULL;

	// Find web token:
	// - in cookie which name is stored in WEB_TOKEN, or
	// - in header 'Authorization' which values is "Bearer TOKEN"
	ngx_str_t cookie_name = ngx_string(WEB_TOKEN);
	ngx_str_t cookie_value = ngx_null_string;
	ngx_int_t rc = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &cookie_name, &cookie_value);
	if (rc != NGX_DECLINED) {
		session.token = from_ngx_str(r->pool, cookie_value);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Web token found in cookie %s: %s", WEB_TOKEN, session.token);
	}
	else {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Web token not found in cookie: %s", WEB_TOKEN);

		if (r->headers_in.authorization) {
			session.authorization = from_ngx_str(r->pool, r->headers_in.authorization->value);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found Authorization header: %s", session.authorization);

			if (strstr(session.authorization, "Bearer")) {
				session.token = ngx_pcalloc(r->pool, strlen(session.authorization) + 1);
				strncpy(session.token, session.authorization + 7, strlen(session.authorization) - 7);
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Web token found in Authorization header: %s", session.token);
			}
			else
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Web token not found in Authorization header");
		}
	}

	// Set some defaults (to be used if no corresponding field is found)
	meta_file.etag = NULL;
	meta_file.md5 = NULL;
	meta_file.filename = NULL;
	meta_file.content_type = NULL;
	meta_file.length = 0;
	meta_file.upload_date = 0;
	meta_file.data = NULL;

	// FIXME: Prepare outbound message to auth server in session->auth_req
	// Format is: our custom JSON with filename, newline, original JWT

	// Query for metadata here over the Unix socket
	char *auth_resp;
	ret = get_metadata(&session, r);
	if (ret)
		return ret;

	// Process metadata
	ret = process_metadata(&meta_file, &session, r);
	free(session->auth_resp);
	if (ret)
		return ret;

	// Process the file (unless we got 404 previously)
	if (! ret) {
		// Init download data
		ret = init_dnld_file(&meta_file, &session, &dnld_file, r);
		if (ret)
			return ret;

		ret = read_fs(&session, &dnld_file, r);
		if (ret)
			return ret;

		// Send the file
		ret = send_file(&session, &dnld_file, r);

		// Unmap memory mapped for sending the file
		if (munmap(dnld_file.data, dnld_file.length) < 0)
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s munmap() error %u", session.id, errno);

		return ret;
	}
}


/**
 * Get file metadata
 */
int get_metadata(session_t *session, ngx_http_request_t *r) {
	// Socket variables
	struct sockaddr_un remote_un;
	int unix_socket, addr_len_un, bytes_in, bytes_out, auth_resp_len, auth_resp_pos;
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
					session->auth_resp = realloc(auth_resp, auth_resp_len + AUTH_BUFFER_CHUNK);
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
ngx_int_t process_metadata(medicloud_file_t *meta_file, session_t *session, ngx_http_request_t *r) {
	const bson_t *doc;
	bson_error_t error;
	bson_iter_t iter;
	const char *bson_key;

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

		if ((! strcmp(bson_key, "status")) && (bson_iter_type(&iter) == BSON_TYPE_INT32)) {
			meta_file->status = bson_iter_int32 (&iter);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s metadata status: %u", session->id, meta_file->status);
		}

		else if ((! strcmp(bson_key, "error")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			meta_file->error = bson_iter_utf8 (&iter, NULL);
			if (strlen(meta_file->error))
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s metadata error: %s", session->id, meta_file->error);
		}

		else if ((! strcmp(bson_key, "filename")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			meta_file->filename = bson_iter_utf8 (&iter, NULL);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s metadata filename: %s", session->id, meta_file->filename);
		}

		else if (! strcmp(bson_key, "length")) {
			if (bson_iter_type(&iter) == BSON_TYPE_INT32)
				meta_file->length = bson_iter_int32 (&iter);
			else if (bson_iter_type(&iter) == BSON_TYPE_INT64)
				meta_file->length = bson_iter_int64 (&iter);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s metadata length: %l", session->id, meta_file->length);
		}

		else if ((! strcmp(bson_key, "content_type")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			meta_file->content_type = bson_iter_utf8 (&iter, NULL);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s metadata content_type: %s", session->id, meta_file->content_type);
		}

		else if ((! strcmp(bson_key, "upload_date")) && (bson_iter_type(&iter) == BSON_TYPE_DATE_TIME)) {
			meta_file->upload_date = bson_iter_date_time (&iter) / 1000;
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s metadata upload_date: %l", session->id, meta_file->upload_date);
		}

		else if ((! strcmp(bson_key, "ETag")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			meta_file->etag = bson_iter_utf8 (&metadata, NULL);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s metadata etag: %s", session->id, meta_file->etag);
		}
	}

	return (meta_file->status == 200) ? 0 : meta_file->status;
}

/**
 * Init file for download
 */
ngx_int_t init_dnld_file(medicloud_file_t *meta_file, session_t *session, medicloud_file_t *dnld_file, ngx_http_request_t *r) {
	// Set ETag: use MD5 field if no ETag field found, use defailt if no MD5 field found
	if (meta_file->etag) {
		dnld_file->etag = ngx_pcalloc(r->pool, strlen(meta_file->etag) + 1);
		strcpy(dnld_file->etag, meta_file->etag);
	}
	else if (meta_file->md5) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s ETag not found, using MD5 %s", session->id, meta_file->md5);
		dnld_file->etag = ngx_pcalloc(r->pool, strlen(meta_file->md5) + 1);
		strcpy(dnld_file->etag, meta_file->md5);
	}
	else {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s ETag and MD5 not found, using default %s", session->id, DEFAULT_ETAG);
		dnld_file->etag = ngx_pcalloc(r->pool, strlen(DEFAULT_ETAG) + 1);
		strcpy(dnld_file->etag, DEFAULT_ETAG);
	}

	// Compare file ETag with a supplied ETag, if any, and return 304 on match
	// NB: This will also match when weak check is requested (W/"1234567890")
	if (session->if_none_match && strstr(session->if_none_match, dnld_file->etag)) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s has a match on ETag, sending 304", session->id);
		return NGX_HTTP_NOT_MODIFIED;
	}

	// Set filename
	if (meta_file->filename) {
		dnld_file->filename = ngx_pcalloc(r->pool, strlen(meta_file->filename) + 1);
		strcpy(dnld_file->filename, meta_file->filename);
	}
	else {
		dnld_file->filename = ngx_pcalloc(r->pool, strlen(DEFAULT_FILENAME) + 1);
		strcpy(dnld_file->filename, DEFAULT_FILENAME);
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s filename not found, using default %s", session->id, DEFAULT_FILENAME);
	}

	// Set content type
	if (meta_file->content_type) {
		dnld_file->content_type = ngx_pcalloc(r->pool, strlen(meta_file->content_type) + 1);
		strcpy(dnld_file->content_type, meta_file->content_type);
	}
	else {
		dnld_file->content_type = ngx_pcalloc(r->pool, strlen(DEFAULT_CONTENT_TYPE) + 1);
		strcpy(dnld_file->content_type, DEFAULT_CONTENT_TYPE);
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s content type not found, using default %s", session->id, DEFAULT_CONTENT_TYPE);
	}

	// Set upload date
	if (meta_file->upload_date)
		dnld_file->upload_date = meta_file->upload_date;
	else {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s unable to find upload date, using current time", session->id);
		dnld_file->upload_date = time(NULL);
	}

	// Set length
	if (meta_file->length)
		dnld_file->length = meta_file->length;
	else {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s length not found ot empty file", session->id);
		return NGX_HTTP_OK;
	}

	return 0;
}

/**
 * Read file from Filesystem
 */
ngx_int_t read_fs(session_t *session, medicloud_file_t *dnld_file, ngx_http_request_t *r) {
	// Get path
	int i, len, pos=0, fd;
	char *path;

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

	if ((dnld_file->data = mmap(NULL, dnld_file->length, PROT_READ, MAP_SHARED, fd, 0)) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s mmap() error %u", session->id, path, errno);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (close(fd) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s close() error %u", session->id, path, errno);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	return 0;
}

/**
 * Send file to client
 */
ngx_int_t send_file(session_t *session, medicloud_file_t *dnld_file, ngx_http_request_t *r) {
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
	r->headers_out.content_length_n = dnld_file->length;

	// Content-Type 
	r->headers_out.content_type.len = strlen(dnld_file->content_type);
	r->headers_out.content_type.data = (u_char*)dnld_file->content_type;
	
	// Last-Modified
	r->headers_out.last_modified_time = dnld_file->upload_date;

	// ETag
	b1_len = strlen(dnld_file->etag) + 2;
	ngx_buf_t *b1 = ngx_create_temp_buf(r->pool, b1_len);
	b1->last = ngx_sprintf(b1->last, "\"%s\"", dnld_file->etag);

	r->headers_out.etag = ngx_list_push(&r->headers_out.headers);
	r->headers_out.etag->hash = 1;
	r->headers_out.etag->key.len = sizeof(HEADER_ETAG) - 1;
	r->headers_out.etag->key.data = (u_char*)HEADER_ETAG;
	r->headers_out.etag->value.len = b1_len;
	r->headers_out.etag->value.data = b1->start;

	// Attachment: if is_attachment
	if (session->is_attachment) {
		// URI-encode the file name?
		curl = curl_easy_init();
		if (curl) {
			encoded = curl_easy_escape(curl, dnld_file->filename, strlen(dnld_file->filename));
			if (encoded) {
				curl_encoded = true;
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s using URI-encoded filename %s", session->id, encoded);
			}
			else {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s unable to URI-encode filename %s", session->id, dnld_file->filename);
				encoded = dnld_file->filename;
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

	// Accept-ranges (not strictly necessary, but good to have)
	r->headers_out.accept_ranges = ngx_list_push(&r->headers_out.headers);
	r->headers_out.accept_ranges->hash = 1;
	r->headers_out.accept_ranges->key.len = sizeof(HEADER_ACCEPT_RANGES) - 1;
	r->headers_out.accept_ranges->key.data = (u_char*)HEADER_ACCEPT_RANGES;
	r->headers_out.accept_ranges->value.len = sizeof("none") - 1;
	r->headers_out.accept_ranges->value.data = (u_char*)"none";

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

	// Fill the buffer
	b->pos = dnld_file->data;
	b->last = dnld_file->data + dnld_file->length;
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

