/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "ngx_http_cdn_module.h"
#include "request_json.h"
#include "request_mysql.h"
#include "request_sql.h"
#include "transport_mysql.h"
#include "transport_unix.h"
#include "utils.h"

/**
 * Module initialisation
 */

ngx_int_t ngx_http_cdn_module_init (ngx_cycle_t *cycle) {
	int ret; 

	if ((ret = mysql_library_init(0, NULL, NULL)) > 0) {
		ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Failed to init MySQL library: error %l.", ret);
		return NGX_ERROR;
	}

	return NGX_OK;
}

/**
 * Module termination
 */

void ngx_http_cdn_module_end (ngx_cycle_t *cycle) {
	mysql_library_end();
}

/**
 * Create location configuration
 */
void* ngx_http_cdn_create_loc_conf(ngx_conf_t* cf) {
	ngx_http_cdn_loc_conf_t* loc_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cdn_loc_conf_t));
	if (loc_conf == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Failed to allocate %l bytes for location config.", sizeof(ngx_http_cdn_loc_conf_t));
		return NGX_CONF_ERROR;
	}

	return loc_conf;
}

/**
 * Merge location configuration
 */
char* ngx_http_cdn_merge_loc_conf(ngx_conf_t* cf, void* void_parent, void* void_child) {
	ngx_http_cdn_loc_conf_t *parent = void_parent;
	ngx_http_cdn_loc_conf_t *child = void_child;

	ngx_conf_merge_str_value(child->fs_root, parent->fs_root, DEFAULT_FS_ROOT);
	ngx_conf_merge_str_value(child->fs_depth, parent->fs_depth, DEFAULT_FS_DEPTH);
	ngx_conf_merge_str_value(child->request_type, parent->request_type, DEFAULT_REQUEST_TYPE);
	ngx_conf_merge_str_value(child->transport_type, parent->transport_type, DEFAULT_TRANSPORT_TYPE);
	ngx_conf_merge_str_value(child->unix_socket, parent->unix_socket, DEFAULT_unix_socket);
	ngx_conf_merge_str_value(child->jwt_cookie, parent->jwt_cookie, DEFAULT_JWT_COOKIE);
	ngx_conf_merge_str_value(child->jwt_header, parent->jwt_header, DEFAULT_JWT_HEADER);
	ngx_conf_merge_str_value(child->jwt_key, parent->jwt_key, DEFAULT_JWT_KEY);
	ngx_conf_merge_str_value(child->jwt_field, parent->jwt_field, DEFAULT_JWT_FIELD);
	ngx_conf_merge_str_value(child->json_extended, parent->json_extended, DEFAULT_JSON_EXTENDED);
	ngx_conf_merge_str_value(child->sql_dsn, parent->sql_dsn, DEFAULT_SQL_DSN);
	ngx_conf_merge_str_value(child->sql_query, parent->sql_query, DEFAULT_SQL_QUERY);

	return NGX_CONF_OK;
}

/**
 * Init module and set handler
 */
char *ngx_http_cdn_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_cdn_handler;

    return NGX_CONF_OK;
}

/**
 * Content handler
 */
ngx_int_t ngx_http_cdn_handler(ngx_http_request_t *r) {
	ngx_http_cdn_loc_conf_t *cdn_loc_conf;
	ngx_int_t ret;
	ngx_table_elt_t *h;
	cdn_file_t *metadata;
	char *s0, *s1, *s2;
	char *str1, *saveptr1;
	struct tm ltm;

	cdn_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_cdn_module);

	// CORS handling
	if (r->method & (NGX_HTTP_OPTIONS)) {
		// There will be no body
		r->header_only = 1;
		r->allow_ranges = 0;

		// Status
		r->headers_out.status = NGX_HTTP_OK;

		// Content-Length
		r->headers_out.content_length_n = 0;

		// Add Access-Control-Allow-Origin header
		h = ngx_list_push(&r->headers_out.headers);
		if (h == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to add new output header: %s.", HEADER_ACCESS_CONTROL_ALLOW_ORIGIN);
			return NGX_ERROR;
		}
		h->hash = 1;
		ngx_str_set(&h->key, HEADER_ACCESS_CONTROL_ALLOW_ORIGIN);
		ngx_str_set(&h->value, DEFAULT_ACCESS_CONTROL_ALLOW_ORIGIN);

		// Add Access-Control-Allow-Methods header
		h = ngx_list_push(&r->headers_out.headers);
		if (h == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to add new output header: %s.", HEADER_ACCESS_CONTROL_ALLOW_METHODS);
			return NGX_ERROR;
		}
		h->hash = 1;
		ngx_str_set(&h->key, HEADER_ACCESS_CONTROL_ALLOW_METHODS);
		ngx_str_set(&h->value, DEFAULT_ACCESS_CONTROL_ALLOW_METHODS);

		// Add Access-Control-Allow-Headers header
		h = ngx_list_push(&r->headers_out.headers);
		if (h == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to add new output header: %s.", HEADER_ACCESS_CONTROL_ALLOW_HEADERS);
			return NGX_ERROR;
		}
		h->hash = 1;
		ngx_str_set(&h->key, HEADER_ACCESS_CONTROL_ALLOW_HEADERS);
		ngx_str_set(&h->value, DEFAULT_ACCESS_CONTROL_ALLOW_HEADERS);

		// Send headers
		return ngx_http_send_header(r);
	}

	// Check if we should serve this request
	if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
		return NGX_DECLINED;
	}

	// Prepare session management data
	session_t session;
	session.fs_depth = atoi(from_ngx_str(r->pool, cdn_loc_conf->fs_depth));
	session.fs_root = from_ngx_str(r->pool, cdn_loc_conf->fs_root);
	session.request_type = from_ngx_str(r->pool, cdn_loc_conf->request_type);
	session.transport_type = from_ngx_str(r->pool, cdn_loc_conf->transport_type);
	session.jwt_cookie = from_ngx_str(r->pool, cdn_loc_conf->jwt_cookie);
	session.jwt_header = from_ngx_str(r->pool, cdn_loc_conf->jwt_header);
	session.jwt_key = from_ngx_str(r->pool, cdn_loc_conf->jwt_key);
	session.jwt_json = NULL;
	session.jwt_field = NULL;
	session.jwt_value = NULL;
	session.json_extended = from_ngx_str(r->pool, cdn_loc_conf->json_extended);
	session.sql_dsn = from_ngx_str(r->pool, cdn_loc_conf->sql_dsn);
	session.sql_query = from_ngx_str(r->pool, cdn_loc_conf->sql_query);
	session.headers = NULL;
	session.headers_count = 0;
	session.cookies = NULL;
	session.cookies_count = 0;
	session.hdr_if_none_match = NULL;
	session.hdr_if_modified_since = -1;
	session.unix_socket = from_ngx_str(r->pool, cdn_loc_conf->unix_socket);
	session.unix_request = NULL;
	session.unix_response = NULL;

	// Init file metadata
	metadata = ngx_pcalloc(r->pool, sizeof(cdn_file_t));
	if (metadata == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata.", sizeof(cdn_file_t));
		return NGX_ERROR;
	}

	metadata->filename = NULL;
	metadata->path = NULL;
	metadata->content_type = NULL;
	metadata->content_disposition = NULL;
	metadata->etag = NULL;
	metadata->data = NULL;
	metadata->length = -1;
	metadata->upload_date = -1;
	metadata->status = -1;

	// Attach metadata to request for further use
	ngx_http_set_ctx(r, metadata, ngx_http_cdn_module);

	// URI
	session.uri = from_ngx_str(r->pool, r->uri);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found URI: %s", session.uri);

	// Extract file ID
	// URL format: http://cdn.example.com/some-file-id
	s0 = from_ngx_str(r->pool, r->uri);
	str1 = strtok_r(s0, "/", &saveptr1);
	if (str1 == NULL)
		return NGX_HTTP_BAD_REQUEST;

	metadata->file = ngx_pnalloc(r->pool, strlen(str1) + 1);
	if (metadata->file == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for URI pasring.", strlen(str1) + 1);
		return NGX_ERROR;
	}
	strcpy(metadata->file, str1);

	// Get path
	ret = get_path(&session, metadata, r);
	if (ret)
		return ret;

	// Get stat for the file (will return 404 if file was not found, or 500 on any other error)
	if ((metadata->length < 0) || (metadata->upload_date < 0)) {
		ret = get_stat(metadata, r);
		if (ret)
			return ret;
	}

	// Extract common headers: Authorisation, If-Modified-Since, If-None-Match
	if (r->headers_in.authorization) {
		if (get_header(&session, r, HEADER_AUTHORIZATION, r->headers_in.authorization->value))
			return NGX_ERROR;
	}

	if (r->headers_in.if_modified_since) {
		if (get_header(&session, r, HEADER_IF_MODIFIED_SINCE, r->headers_in.if_modified_since->value))
			return NGX_ERROR;

		s1 = from_ngx_str(r->pool, r->headers_in.if_modified_since->value);
		if (strptime(s1, "%a, %d %b %Y %H:%M:%S", &ltm)) {
			session.hdr_if_modified_since = mktime(&ltm);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Converted value for header If-Modified-Since to timestamp: %l", session.hdr_if_modified_since);
		}
		else
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to convert header If-Modified-Since to timestamp: %s", s1);
	}

	if (r->headers_in.if_none_match) {
		if (get_header(&session, r, HEADER_IF_NONE_MATCH, r->headers_in.if_none_match->value))
			return NGX_ERROR;

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

	// TODO: Extract custom headers if requested




	// Extract JWT if specified (i.e. if we have a validation key specified in config)
	if (strcmp(session.jwt_key, DEFAULT_JWT_KEY)) {
		ret = get_jwt(&session, r);
		if (ret)
			return ret;
	}

	// Prepare request (as per the configured request type)
	if (! strcmp(session.request_type, REQUEST_TYPE_JSON))
		ret = request_json(&session, r);
	else if (! strcmp(session.request_type, REQUEST_TYPE_MYSQL))
		ret = request_sql(&session, r);
	if (ret)
		return ret;

	// Query for metadata
	if (! strcmp(session.transport_type, TRANSPORT_TYPE_UNIX)) {
		ret = transport_unix(&session, r);
		if (session.unix_request)
			bson_free(session.unix_request);
	}
	else if (! strcmp(session.transport_type, TRANSPORT_TYPE_MYSQL))
		ret = transport_mysql(&session, r);

	if (ret)
		return ret;

	// Process response (as per the configured request type)
	if (! strcmp(session.request_type, REQUEST_TYPE_JSON)) {
		ret = response_json(&session, metadata, r);
		if (session.unix_response)
			free(session.unix_response);
	}
	else if (! strcmp(session.request_type, REQUEST_TYPE_MYSQL)) {
		ret = response_json(&session, metadata, r);
		if (session.mysql_result)
			mysql_free_result(session.mysql_result);
	}

	if (ret)
		return ret;

	// Check metadata
	ret = metadata_check(&session, metadata, r);
	if (ret)
		return ret;

	// Process the file
	ret = read_fs(&session, metadata, r);
	if (ret)
		return ret;

	// Send the file
	ret = send_file(&session, metadata, r);
	if (ret) {
		cleanup(metadata, r);
		return ret;
	}

	// NB: The mapped file will be unmapped by the cleanup handler once data is sent to client

	return NGX_OK;
}

/**
 * Read file
 */
ngx_int_t read_fs(session_t *session, cdn_file_t *metadata, ngx_http_request_t *r) {
	int fd, ret;
	ngx_http_cleanup_t *c;

	// Get path if not set so far
	if (! metadata->path) {
		ret = get_path(session, metadata, r);
		if (ret)
			return ret;
	}

	// Get stat if not set
	if ((metadata->length < 0) || (metadata->upload_date < 0)) {
		ret = get_stat(metadata, r);
		if (ret)
			return ret;
	}

	// If file unmodifed, return 304
	if (session->hdr_if_modified_since >= metadata->upload_date)
		return NGX_HTTP_NOT_MODIFIED;

	// Read the file: use mmap to map the physical file to memory
	if ((fd = open(metadata->path, O_RDONLY)) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s open() error %s", metadata->file, metadata->path, strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (r->method & (NGX_HTTP_GET)) {
		// Map the physical file to memory
		if ((metadata->data = mmap(NULL, metadata->length, PROT_READ, MAP_SHARED, fd, 0)) < 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s mmap() error %s", metadata->file, metadata->path, strerror(errno));
			if (close(fd) < 0)
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s close() error %s", metadata->file, metadata->path, strerror(errno));
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		// Set cleanup handler to unmap the file
		c = ngx_pcalloc(r->pool, sizeof(ngx_http_cleanup_t));
		if (c == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for cleanup.", sizeof(ngx_http_cleanup_t));
			return NGX_ERROR;
		}
		c->handler = ngx_http_cdn_cleanup;
		c->data = r;
		r->cleanup = c;
	}

	if (close(fd) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s close() error %s", metadata->file, metadata->path, strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	return NGX_OK;
}

/**
 * Send file to client
 */
ngx_int_t send_file(session_t *session, cdn_file_t *metadata, ngx_http_request_t *r) {
	int b1_len, b2_len;
	char *encoded = NULL;
	bool curl_encoded = false;
	CURL *curl;
    ngx_buf_t *b, *b1, *b2;
    ngx_chain_t *out = NULL;
	ngx_table_elt_t *h;
	ngx_int_t ret;

	// HTTP status
	r->headers_out.status = NGX_HTTP_OK;

	// Content-Length
	// NB: Nginx violates RFC 2616 and mandates the return of 0 in case of HEAD, otherwise the response in never completes
	if (r->method & (NGX_HTTP_GET))
		r->headers_out.content_length_n = metadata->length;
	else
		r->headers_out.content_length_n = 0;

	// Content-Type 
	r->headers_out.content_type.len = strlen(metadata->content_type);
	r->headers_out.content_type.data = (u_char*)metadata->content_type;
	
	// Last-Modified
	r->headers_out.last_modified_time = metadata->upload_date;

	// ETag
	b1_len = strlen(metadata->etag) + 2;
	b1 = ngx_create_temp_buf(r->pool, b1_len);
	if (b1 == NULL) {
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
		else 
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s unable to init curl for URI-encoding", metadata->file);

		// Add Content-Disposition header
		// headers['Content-Disposition'] = 'attachment; filename="' + encodeURIComponent(this.file.filename) + '";'
		// NB: It is not in the standard Nginx header table, so add it as custom header
		h = ngx_list_push(&r->headers_out.headers);
		if (h == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to add new output header.");
		    return NGX_ERROR;
		}
		h->hash = 1;

		ngx_str_set(&h->key, HEADER_CONTENT_DISPOSITION);

		b2_len = 23 + strlen(encoded);
		b2 = ngx_create_temp_buf(r->pool, b2_len);
		if (b2 == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate buffer for Content-Disposition header.");
			return NGX_ERROR;
		}
		b2->last = ngx_sprintf(b2->last, "attachment; filename=\"%s\"", encoded);
		h->value.len = b2_len;
		h->value.data = b2->start;

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

	// Send headers
	ret = ngx_http_send_header(r);
	if (ret == NGX_ERROR || ret > NGX_OK)
		return ret;

	// Map the file we are going to serve in the body
	if (r->method & (NGX_HTTP_GET)) {
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
	}

	// Send the body, and return the status code of the output filter chain
	if (r->method & (NGX_HTTP_GET))
		ret = ngx_http_output_filter(r, out);

	return ret;
} 

/**
 * Cleanup (unmap mapped file after serving)
 */
void cleanup(cdn_file_t *metadata, ngx_http_request_t *r) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Running connection cleanup.");
    
    if (metadata->data && (munmap(metadata->data, metadata->length) < 0))
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s munmap() error %s", metadata->file, strerror(errno));
}

/**
 * Cleanup (unmap mapped file after serving)
 */
void ngx_http_cdn_cleanup(void *a) {
    ngx_http_request_t *r = (ngx_http_request_t *)a;
    cdn_file_t *metadata = ngx_http_get_module_ctx(r, ngx_http_cdn_module);
	cleanup(metadata, r);
}

/**
 * Extract a header
 */
ngx_int_t get_header(session_t *session, ngx_http_request_t *r, char *name, ngx_str_t value) {
	cdn_kvp_t *headers;

	// NB: Nginx pool does not have realloc, so we need to emulate it

	// Always allocate memory
	headers = ngx_pnalloc(r->pool, sizeof(cdn_kvp_t) * (session->headers_count + 1));
	if (headers == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for %l headers KVP.", sizeof(cdn_kvp_t) * (session->headers_count + 1), session->headers_count + 1);
		return NGX_ERROR;
	}

	// If we have previous values, copy them
	if (session->headers_count)
		memcpy(headers, session->headers, sizeof(cdn_kvp_t) * session->headers_count);
	session->headers = headers;

	// Save header name
	session->headers[session->headers_count].value = ngx_pcalloc(r->pool, strlen(name) + 1);
	strcpy(session->headers[session->headers_count].value, name);

	// Extract header value
	session->headers[session->headers_count].value = from_ngx_str(r->pool, value);

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found header %s: %s", name, session->headers[session->headers_count].value);

	session->headers_count ++;

	return NGX_OK;
}

/**
 * Extract JWT
 */
ngx_int_t get_jwt(session_t *session, ngx_http_request_t *r) {
	time_t exp;
	char *hdr_authorization;
	bool match = false;
	int i, j;
	ngx_int_t ret;
	ngx_str_t cookie_name, cookie_value;
	ngx_table_elt_t *h;
	ngx_list_part_t *part;

	// Try to find JWT in Authorization header
	if (r->headers_in.authorization) {
		hdr_authorization = from_ngx_str(r->pool, r->headers_in.authorization->value);

		if (strstr(hdr_authorization, "Bearer")) {
			session->jwt_json = ngx_pcalloc(r->pool, strlen(hdr_authorization) + 1);
			strncpy(session->jwt_json, hdr_authorization + 7, strlen(hdr_authorization) - 7);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "JWT found in Authorization header: %s", session->jwt_json);
		}
	}

	// Try to find JWT in a custom header
	if (strcmp(session->jwt_header, DEFAULT_JWT_HEADER)) {
		part = &r->headers_in.headers.part;
		for (i=0; i < r->headers_in.headers.nalloc; i++) {
			h = part->elts;
			for (j=0; j < part->nelts; j++) {
				if (! ngx_strncasecmp( h[j].key.data, (u_char *) session->jwt_header, h[j].key.len)) {
					session->jwt_json = from_ngx_str(r->pool, h[j].value);
					match = true;
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "JWT found in header %s: %s", session->jwt_header, session->jwt_json);
					break;
				}
			}

			if (match)
				break;

			part = part->next;
		}
	}

	// If cookie name given in config, try to find the cookie and to extract JWT from it
	if (strcmp(session->jwt_cookie, DEFAULT_JWT_COOKIE)) {
		cookie_name.len = strlen(session->jwt_cookie);
		cookie_name.data = (u_char *) session->jwt_cookie;

		ret = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &cookie_name, &cookie_value);
		if (ret == NGX_DECLINED) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Cookie %s for JWT not found", session->jwt_cookie);
		}
		else {
			session->jwt_json = from_ngx_str(r->pool, cookie_value);
		}
	}

	// If neither cookie nor header was given or JWT not found, give up
	if (! session->jwt_json) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT not found, declining request");
		return NGX_HTTP_UNAUTHORIZED;
	}

	// Validate and extract the token
	if ((ret = jwt_decode(&session->jwt, session->jwt_json, (unsigned char*)session->jwt_key, strlen(session->jwt_key)))) {
		if (ret == EINVAL) {
			// Invalid signature
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s invalid signature", session->jwt_json);
			return NGX_HTTP_UNAUTHORIZED;
		}
		else {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s system error %u while decoding", session->jwt_json, ret);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	// Check expiration
	exp = jwt_get_grant_int(session->jwt, "exp");
	if (errno == ENOENT) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to find claim EXP", session->jwt_json);
		return NGX_HTTP_UNAUTHORIZED;
	}
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Token %s found claim EXP %l", session->jwt_json, exp);
	if (exp < time(NULL)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s has expired: EXP is %l, now is %l", session->jwt_json, exp, time(NULL));
		return NGX_HTTP_UNAUTHORIZED;
	}

	// Extract the value from payload that we'll use in authentication
	session->jwt_value = jwt_get_grant(session->jwt, session->jwt_field);
	if (session->jwt_value) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Token %s found claim %s %s", session->jwt_json, session->jwt_field, session->jwt_value);
	}
	else {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to find claim %s", session->jwt_json, session->jwt_field);
		return NGX_HTTP_UNAUTHORIZED;
	}

	return NGX_OK;
}

/**
 * Check metdata for errors
 */
ngx_int_t metadata_check(session_t *session, cdn_file_t *metadata, ngx_http_request_t *r) {
	// Metadata: check for error
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
 * Helper: get the full path from a file name
 */
ngx_int_t get_path(session_t *session, cdn_file_t *metadata, ngx_http_request_t *r) {
	int i, len, pos=0;

	len = strlen(session->fs_root) + 1 + 2 * session->fs_depth + strlen(metadata->file) + 1;
	metadata->path = ngx_pcalloc(r->pool, len);
	if (metadata->path == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for path.", len);
		return NGX_ERROR;
	}
	memset(metadata->path, '\0', len);

	memcpy(metadata->path, session->fs_root, strlen(session->fs_root));
	pos += strlen(session->fs_root);

	memcpy(metadata->path + pos, "/", 1);
	pos ++;

	for (i=0; i < session->fs_depth; i++) {
		memcpy(metadata->path + pos, metadata->file + i, 1);
		pos ++;
		memcpy(metadata->path + pos, "/", 1);
		pos ++;
	}

	memcpy(metadata->path + pos, metadata->file, strlen(metadata->file));

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s using path: %s", metadata->file, metadata->path);

	return NGX_OK;
}

/**
 * Helper: get stat of a file
 */
ngx_int_t get_stat(cdn_file_t *metadata, ngx_http_request_t *r) {
	struct stat statbuf;
	int fd;

	// Open file
	if ((fd = open(metadata->path, O_RDONLY)) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s open() error %s", metadata->file, metadata->path, strerror(errno));
		if (errno == ENOENT)
			return NGX_HTTP_NOT_FOUND;
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	fstat(fd, &statbuf);
	if (metadata->length < 0) 
		metadata->length = statbuf.st_size;
	if (metadata->upload_date < 0)
		metadata->upload_date = statbuf.st_mtime;

	if (close(fd) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s close() error %s", metadata->file, metadata->path, strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	return NGX_OK;
}

