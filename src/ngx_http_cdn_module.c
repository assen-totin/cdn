/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "ngx_http_cdn_module.h"
#include "auth_jwt.h"
#include "auth_session->h"
#include "request_json.h"
#include "request_mongo.h"
#include "request_mysql.h"
#include "request_oracle.h"
#include "request_sql.h"
#include "request_xml.h"
#include "transport_http.h"
#include "transport_mongo.h"
#include "transport_mysql.h"
#include "transport_oracle.h"
#include "transport_socket.h"
#include "utils.h"

/**
 * Module initialisation
 */

ngx_int_t ngx_http_cdn_module_init (ngx_cycle_t *cycle) {
	int ret; 

#ifdef CDN_ENABLE_MONGO
	// Init Mongo
	mongoc_init();
#endif

#ifdef CDN_ENABLE_MYSQL
	// Init MySQL
	if ((ret = mysql_library_init(0, NULL, NULL)) > 0) {
		ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Failed to init MySQL library: error %l.", ret);
		return NGX_ERROR;
	}
#endif

#ifdef CDN_ENABLE_ORACLE
	// Init Oracle
	if (! OCI_Initialize(NULL, NULL, OCI_ENV_DEFAULT | OCI_ENV_CONTEXT | OCI_ENV_THREADED)) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "Failed to init Oracle OCI library: %s", OCI_ErrorGetString(OCI_GetLastError()));
		return NGX_ERROR;
	}
#endif

	// Check libxml version
	LIBXML_TEST_VERSION;

	// Init cURL
	curl_global_init(CURL_GLOBAL_DEFAULT);

	return NGX_OK;
}

/**
 * Module termination
 */

void ngx_http_cdn_module_end (ngx_cycle_t *cycle) {
#ifdef CDN_ENABLE_MYSQL
	mysql_library_end();
#endif
#ifdef CDN_ENABLE_ORACLE
	OCI_Cleanup();
#endif
}

/**
 * Create location configuration
 */
void* ngx_http_cdn_create_loc_conf(ngx_conf_t* cf) {
	ngx_http_cdn_loc_conf_t *loc_conf;

	if ((loc_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cdn_loc_conf_t))) == NULL) {
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
	ngx_conf_merge_str_value(child->unix_socket, parent->unix_socket, DEFAULT_UNIX_SOCKET);
	ngx_conf_merge_str_value(child->tcp_host, parent->tcp_host, DEFAULT_TCP_HOST);
	ngx_conf_merge_str_value(child->tcp_port, parent->tcp_port, DEFAULT_TCP_PORT);
	ngx_conf_merge_str_value(child->auth_cookie, parent->auth_cookie, DEFAULT_AUTH_COOKIE);
	ngx_conf_merge_str_value(child->auth_header, parent->auth_header, DEFAULT_AUTH_HEADER);
	ngx_conf_merge_str_value(child->auth_type, parent->auth_type, DEFAULT_AUTH_METOD);
	ngx_conf_merge_str_value(child->jwt_key, parent->jwt_key, DEFAULT_JWT_KEY);
	ngx_conf_merge_str_value(child->jwt_field, parent->jwt_field, DEFAULT_JWT_FIELD);
	ngx_conf_merge_str_value(child->all_headers, parent->all_headers, DEFAULT_ALL_HEADERS);
	ngx_conf_merge_str_value(child->all_cookies, parent->all_cookies, DEFAULT_ALL_COOKIES);
	ngx_conf_merge_str_value(child->db_dsn, parent->db_dsn, DEFAULT_DB_DSN);
	ngx_conf_merge_str_value(child->sql_insert, parent->sql_insert, DEFAULT_SQL_QUERY);
	ngx_conf_merge_str_value(child->sql_delete, parent->sql_delete, DEFAULT_SQL_QUERY);
	ngx_conf_merge_str_value(child->sql_select, parent->sql_select, DEFAULT_SQL_QUERY);
	ngx_conf_merge_str_value(child->http_url, parent->http_url, DEFAULT_HTTP_URL);
	ngx_conf_merge_str_value(child->mongo_db, parent->mongo_db, DEFAULT_MONGO_DB);
	ngx_conf_merge_str_value(child->mongo_collection, parent->mongo_collection, DEFAULT_MONGO_COLLECTION);
	ngx_conf_merge_str_value(child->cors_origin, parent->cors_origin, DEFAULT_ACCESS_CONTROL_ALLOW_ORIGIN);

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

///// DEBUG POST
/**
 * Read a line from current position
 */
char *mpfd_get_line(ngx_http_request_t *r, char *begin) {
	char *end, *ret; 

	end = strstr(begin, "\r\n");
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Header line length: %l", end - begin);

	// Sanity check - line should exceed 1000 bytes
	if ((end - begin) > 1024) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Header line too long: %l", end - begin);
		return NULL;
	}

	// Prepare reply
	if ((ret = ngx_pcalloc(r->pool, end - begin + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for upload part line.", end - begin + 1);
		return NULL;
	}

	strncpy(ret, begin, end - begin);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found header line: %s", ret);

	return ret;
}

/**
 * Find a value from a key=value pair, present in a bigger string (haystack), when given the key
 * E.g. knowing 'key' from 'lala; key="value"; bebe' returns "value"
 */
char *mpfd_get_value(ngx_http_request_t *r, char *haystack, char *needle) {
	char *begin, *end, *ret;

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Looking for needle %s in haystack %s", needle, haystack);

	// Find the beginning of the needle
	if (! (begin = strcasestr(haystack, needle))) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Needle %s not found in haystack %s", needle, haystack);
        return NULL;
    }

	// Move forward with the length of the needle, e.g. key=
    begin += strlen(needle) + 1;

	// Check if we have a trailing semicolon; 
	// It will be absent if we are the last key=value pair in the string, so use everything till the end of the string
	end = strstr(begin, ";");
    if (! end)
		end = begin + strlen(begin);

	// Prepare return value and copy the value from the pair there
	if ((ret = ngx_pcalloc(r->pool, end - begin + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for upload param value.", end - begin + 1);
		return NULL;
	}
	strncpy(ret, begin, end - begin);

	// Remove quotes which may surround the value
	if (strstr(ret, "\"")) {
		memset(ret + strlen(ret) - 1, '\0', 1);
		ret ++;
    }

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found value for needle %s: %s", needle, ret);
	return ret;
}

/**
 * Read the value from a header up to the first demicolon, if any
 */
char *mpfd_get_header(ngx_http_request_t *r, char *line, char *header) {
	char *begin, *end, *ret;

	// Check if we are the proper header
	if ((begin = strcasestr(line, header)) == NULL)
		return NULL;

	// Move to beginning of content
	begin += strlen(header) + 2;

	// Check for trailing semicolon
	if (strstr(begin, ";"))
		end = strstr(begin, ";");
	else
		end = begin + strlen(begin);

	if ((ret = ngx_pcalloc(r->pool, end - begin + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for upload part header %s", end - begin + 1, header);
		return NULL;
	}

	strncpy(ret, begin, end - begin);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found value for upload part header %s: %s", header, ret);

	return ret;
}


//client_body_buffer_size IS THE DIRECTIVE THAT GOVERNS WHEN TEMP FILE WILL BE USED! DEFAULT: 16k
//client_max_body_size IS THE MAX UPLOAD SIZE. DEFAULT: 1m

static void ngx_http_cdn_body_handler (ngx_http_request_t *r);

static void ngx_http_cdn_body_handler (ngx_http_request_t *r) {
	off_t len = 0, len_buf;
	ngx_buf_t *b;
	ngx_chain_t out, *bufs;
	char *content_length_z, *content_type, *boundary, *line;
	long content_length;
	int upload_content_type, file_fd, file_size;
	uint64_t hash[2];
	session_t *session;
	metadata_t *metadata;

	// Check if we have body
	if (r->request_body == NULL) {
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	// Init session
	if ((session = ngx_pcalloc(r->pool, sizeof(session_t))) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for session.", sizeof(session_t));
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	// Init metadata
	if ((metadata = ngx_pcalloc(r->pool, sizeof(metadata_t))) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata.", sizeof(metadata_t));
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

//FIXME:
//session->fs_root
//session->fs_depth

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Request body is ready for processing.");

	// Extract content type from header
	content_type = from_ngx_str(r->pool, r->headers_in.content_type->value);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload Content-Type: %s", content_type);
	if (strstr(content_type, CONTENT_TYPE_MPFD))
		upload_content_type = UPLOAD_CONTENT_TYPE_MPFD;
	else if (strstr(content_type, CONTENT_TYPE_AXWFU))
		upload_content_type = UPLOAD_CONTENT_TYPE_AXWFU;
	else {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Upload Content-Type %s not supported", content_type);
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	// Extract content length from header
	content_length_z = from_ngx_str(r->pool, r->headers_in.content_length->value);
	if (! content_length_z) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Upload Content-Length not set");
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}
	content_length = atol(content_length_z);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload Content-Length: %l", content_length);

	// Use mmap or not?
	char *rb = NULL;
	bool rb_malloc = false;
	long rb_pos = 0;
	bufs = r->request_body->bufs;
	if (bufs && bufs->buf && bufs->buf->in_file) {
		// Use mmap from FD in the buffer
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Request body: using file buffers");
		len = bufs->buf->file_last;

		if ((rb = mmap(NULL, len, PROT_READ, MAP_SHARED, bufs->buf->file->fd, 0)) < 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Request body: mmap() error %s", strerror(errno));
			ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}
	}
	else {
		// Work from memory
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Request body: using memory buffers");

		rb = malloc(content_length);
		if (! rb) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to allocate %l bytes for request body conversion", content_length + 1);
			ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		}
		rb_malloc = true;

		for (bufs = r->request_body->bufs; bufs; bufs = bufs->next) {
			len_buf = ngx_buf_size(bufs->buf);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Request body: found new buffer with size: %l", len_buf);
			len += len_buf;

			memcpy(rb + rb_pos, bufs->buf->start, len_buf);
			rb_pos += len_buf;
		}
	}

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Request body: total length: %l", len);
	if (len != content_length) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error processing request body: Content-Length set to %l, but found %l bytes", content_length, len);
		if (rb_malloc)
			free(rb);
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

//FIXME: Create a cleanup funciton that will free rb if rb_malloc before calling ngx_http_finalize_request and use if everywhere below

	// Process multipart/form-data
	if (upload_content_type == UPLOAD_CONTENT_TYPE_MPFD) {
		// Extract boundary
		if ((boundary = mpfd_get_value(r, content_type, "boundary")) == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to find boundary in Content-Type: %s", content_type);
			ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		char *file_data_begin, *file_data_end, *filename, *file_content_type = NULL, *file_content_transfer_encoding = NULL;
		char *part = rb;
		int cnt_part = 0, cnt_header;
		while (1) {
			char *part_pos;
			char *part_field_name = NULL, *part_filename = NULL, *part_content_type = NULL, *part_content_transfer_encoding = NULL;
			char *part_data_end;

			cnt_part++;
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "PROCESSING NEW PART %l", cnt_part);
			if (cnt_part > 10) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Too many loops while processing parts: %l", cnt_part);
				ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

			// Seek a boundary and move past it + CRLF
			if (! (part_pos = strstr(part, boundary))) {
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "boundary not found in body: %s", boundary);
				ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

			// If next two characters are not CRLF (but rather '--CRLF'), this is the end of the form
			char *tmp = strstr(part_pos, "\r\n");
			if ((tmp - part_pos) != strlen(boundary)) {
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Reached end of form");
				break;
			}

			part_pos += strlen(boundary) + 2;

			cnt_header = 0;
			while (1) {
				cnt_header++;
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "PROCESSING NEW HEADER %l IN PART %l", cnt_header, cnt_part);
				if (cnt_header > 10) {
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Too many loops while processing headers: %l", cnt_part);
					ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
					return;
				}

				// Get a line from the headerss
				if ((line = mpfd_get_line(r, part_pos)) == NULL) {
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Failed to read a header line.");
					ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
					return;
				}

				// If line is empty, this is last line of the header; skip its CRLF and break
				if (strlen(line) == 0) {
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found last line of header.");
					part_pos += 2;
					break;
				}

				// Process Content-Disposition header
				if (strcasestr(line, "Content-Disposition")) {
					part_field_name = mpfd_get_value(r, line, "name");
					part_filename = mpfd_get_value(r, line, "filename");
				}

				// Process Content-Type header
				if (! part_content_type)
					part_content_type = mpfd_get_header(r, line, "Content-Type");

				// Process Content-Transfer-Encoding
				if (! part_content_transfer_encoding)
					part_content_transfer_encoding = mpfd_get_header(r, line, "Content-Transfer-Encoding");

				part_pos += strlen(line) + 2;
			}

			// Move past the CRLF of the empty line to start reading data
			if ((part_data_end = strstr(part_pos, boundary)) == NULL) {
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Unable to find next boundary in body: %s", boundary);
				ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
				return;				
			}
			part_data_end -= 4;	// Go back the CRLF "--" that preceed the boundary
			
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "DATA LENGTH FOR PART %l: %l", cnt_part, part_data_end - part_pos);

			// Remember data begin and end if this part was the file part
			if (part_filename) {
				filename = part_filename;
				file_content_type = part_content_type;
				file_content_transfer_encoding = part_content_transfer_encoding;
				file_data_begin = part_pos;
				file_data_end = part_data_end;
				file_size = file_data_end - file_data_begin;
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Filename %s uploaded data %l", filename, file_data_end - file_data_begin);
			}

			// Move the part forward
			part = data_end;
		}
	}

	// Process application/x-www-form-urlencoded
	else if (upload_content_type == UPLOAD_CONTENT_TYPE_AXWFU) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Upload type %s not supported (yet)", CONTENT_TYPE_AXWFU);
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;		
	}

	// FIXME: Decode file if needed?
	if (file_content_transfer_encoding) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Transfer encoding %s not supported (yet)", file_content_transfer_encoding);
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;	
	}

	// Create file hash
	//FIXME: Add server ID and timestamp somehow?
	murmur3((void *)file_data_begin, file_size, TRULY_RANDOM_NUMBER, (void *) &hash[0]);

	// Convert hash to hex string
	if ((metadata->file = ngx_pcalloc(r->pool, 33)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate 33 bytes for file ID.");
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	sprintf(metadata->file, "%016lx%016lx\n", hash[0], hash[1]);

	// Obtain file path
	if ((ret = get_path(session, metadata, r)) > 0) {
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	// Save file to CDN
	if ((file_fd = open(file->path, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP)) == -1) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to create file %s: %s", file->path, strerror(errno));
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	if (write(file_fd, (const void *)file_data_begin, file_size) < file_size) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to write %l bytes to file %s: %s", file_size, file->path, strerror(errno));
		close(file_fd);
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	close(file_fd);

	// FIXME: Save metadata - to SQL/Mongo or send JSON/XML

	// Cleanup
	if (rb_malloc)
		free(rb);

	// Send output: the file ID
	if ((b = ngx_create_temp_buf(r->pool, NGX_OFF_T_LEN)) == NULL) {
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	b->last = ngx_sprintf(b->pos, "%s", metadata->file);
	b->last_buf = 1;
	b->last_in_chain = 1;

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = b->last - b->pos;

	rc = ngx_http_send_header(r);

	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
		ngx_http_finalize_request(r, rc);
		return;
	}

	out.buf = b;
	out.next = NULL;

	rc = ngx_http_output_filter(r, &out);

	ngx_http_finalize_request(r, rc);
}


/*
-----------------------------18777234483971611453887793901
Content-Disposition: form-data; name="n"; filename="gthomas.doc"
Content-Type: application/msword

lalal
-----------------------------18777234483971611453887793901
Content-Disposition: form-data; name="submit"

Upload Image
-----------------------------18777234483971611453887793901--
*/
///// END DEBUG POST

/**
 * Content handler
 */
ngx_int_t ngx_http_cdn_handler(ngx_http_request_t *r) {
	ngx_http_cdn_loc_conf_t *cdn_loc_conf;
	ngx_int_t ret = NGX_OK;
	ngx_table_elt_t *h;
	session_t *session;
	metadata_t *metadata;
	char *uri, *s0, *s1, *s2, *str1, *saveptr1, *cors_origin;
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
		cors_origin = from_ngx_str(r->pool, cdn_loc_conf->cors_origin);
		h = ngx_list_push(&r->headers_out.headers);
		if (h == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to add new output header: %s.", HEADER_ACCESS_CONTROL_ALLOW_ORIGIN);
			return NGX_ERROR;
		}
		h->hash = 1;
		ngx_str_set(&h->key, HEADER_ACCESS_CONTROL_ALLOW_ORIGIN);
		ngx_str_set(&h->value, cors_origin);

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

	// Init session
	if ((session = ngx_pcalloc(r->pool, sizeof(session_t))) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for session.", sizeof(session_t));
		return NGX_ERROR;
	}

	// Method-specific init
	session->http_method = ngx_pcalloc(r->pool, 8);
	if (r->method & (NGX_HTTP_DELETE)) {
		sprintf(session->http_method, "DELETE");
		session->sql_query = from_ngx_str(r->pool, cdn_loc_conf->sql_select);
		// NB: We'll init the SQL DELETE query later
	}
	else if (r->method & (NGX_HTTP_POST)) {
		sprintf(session->http_method, "POST");
		session->sql_query = from_ngx_str(r->pool, cdn_loc_conf->sql_insert);
	}
	else if (r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)) {
		sprintf(session->http_method, "GET");
		session->sql_query = from_ngx_str(r->pool, cdn_loc_conf->sql_select);
	}
	else {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "HTTP method not supported: %l", r->method);
		return NGX_DECLINED;
	}

	// Prepare session management data
	session->fs_depth = atoi(from_ngx_str(r->pool, cdn_loc_conf->fs_depth));
	session->fs_root = from_ngx_str(r->pool, cdn_loc_conf->fs_root);
	session->request_type = from_ngx_str(r->pool, cdn_loc_conf->request_type);
	session->transport_type = from_ngx_str(r->pool, cdn_loc_conf->transport_type);
	session->auth_cookie = from_ngx_str(r->pool, cdn_loc_conf->auth_cookie);
	session->auth_header = from_ngx_str(r->pool, cdn_loc_conf->auth_header);
	session->auth_type = from_ngx_str(r->pool, cdn_loc_conf->auth_type);
	session->auth_token = NULL;
	session->auth_value = NULL;
	session->all_headers = from_ngx_str(r->pool, cdn_loc_conf->all_headers);
	session->all_cookies = from_ngx_str(r->pool, cdn_loc_conf->all_cookies);
	session->db_dsn = from_ngx_str(r->pool, cdn_loc_conf->db_dsn);
	session->headers = NULL;
	session->headers_count = 0;
	session->cookies = NULL;
	session->cookies_count = 0;
	session->hdr_if_none_match = NULL;
	session->hdr_if_modified_since = -1;
	session->unix_socket = from_ngx_str(r->pool, cdn_loc_conf->unix_socket);
	session->tcp_host = from_ngx_str(r->pool, cdn_loc_conf->tcp_host);
	session->tcp_port = atoi(from_ngx_str(r->pool, cdn_loc_conf->tcp_port));
	session->http_url = from_ngx_str(r->pool, cdn_loc_conf->http_url);
	session->auth_request = NULL;
	session->auth_response = NULL;
	session->curl = NULL;
	session->jwt_key = from_ngx_str(r->pool, cdn_loc_conf->jwt_key);
	session->jwt_json = NULL;
	session->jwt_field = NULL;

	// Init file metadata
	if ((metadata = ngx_pcalloc(r->pool, sizeof(metadata_t))) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata.", sizeof(metadata_t));
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
	uri = from_ngx_str(r->pool, r->uri);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found URI: %s", uri);

	if (r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD | NGX_HTTP_DELETE)) {
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
		if ((ret = get_path(session, metadata, r)) > 0)
			return ret;

		// Get stat for the file (will return 404 if file was not found, or 500 on any other error)
		if ((metadata->length < 0) || (metadata->upload_date < 0)) {
			if ((ret = get_stat(metadata, r)) > 0)
				return ret;
		}

		// Process Header If-Modified-Since
		if (r->headers_in.if_modified_since) {
			s1 = from_ngx_str(r->pool, r->headers_in.if_modified_since->value);
			if (strptime(s1, "%a, %d %b %Y %H:%M:%S", &ltm)) {
				session->hdr_if_modified_since = mktime(&ltm);
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Converted value for header If-Modified-Since to timestamp: %l", session->hdr_if_modified_since);
			}
			else
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to convert header If-Modified-Since to timestamp: %s", s1);
		}

		// Process Header If-None-Match
		if (r->headers_in.if_none_match) {
			session->hdr_if_none_match = from_ngx_str(r->pool, r->headers_in.if_none_match->value);
			s1 = strchr(session->hdr_if_none_match, '"');
			s2 = strrchr(session->hdr_if_none_match, '"');
			if ((s1 == session->hdr_if_none_match) && (s2 == session->hdr_if_none_match + strlen(session->hdr_if_none_match) - 1)) {
				if ((s0 = ngx_pcalloc(r->pool, strlen(session->hdr_if_none_match) - 1)) == NULL) {
					ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for hdr_if_none_match.", strlen(session->hdr_if_none_match) - 1);
					return NGX_ERROR;
				}

				strncpy(s0, session->hdr_if_none_match + 1, strlen(session->hdr_if_none_match) - 2);
				session->hdr_if_none_match = s0;
			}
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found header If-None-Match: %s", session->hdr_if_none_match);
		}
	}

	// TODO: support Range incoming header
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range

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

	if (r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD | NGX_HTTP_DELETE)) {
		// Try to find an authorisation token
		if ((ret = get_auth_token(session, r)) > 0)
			return ret;

		// Extract authentcation token to value
		if (! strcmp(session->auth_type, AUTH_TYPE_JWT)) {
			if ((ret = auth_jwt(session, r)) > 0)
				return ret;
		}
		else if (! strcmp(session->auth_type, AUTH_TYPE_SESSION)) {
			if ((ret = auth_session(session, r)) > 0)
				return ret;
		}
	}

///// DEBUG IPOST

if (r->method & (NGX_HTTP_POST)) {
	// Set body handler
	ret = ngx_http_read_client_request_body(r, ngx_http_cdn_body_handler); 
	if (ret >= NGX_HTTP_SPECIAL_RESPONSE)
		return ret;

	return NGX_DONE;
}

///// END DEBUG POST

	// Prepare request (as per the configured request type)
	if (! strcmp(session->request_type, REQUEST_TYPE_JSON))
		ret = request_json(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_MONGO))
		ret = request_mongo(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_MYSQL))
		ret = request_sql(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_ORACLE))
		ret = request_sql(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_XML))
		ret = request_xml(session, metadata, r);

	if (ret)
		return ret;

	// Query for metadata based on transport
	if (! strcmp(session->transport_type, TRANSPORT_TYPE_HTTP))
		ret = transport_http(session, r);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_MONGO))
		ret = transport_mongo(session, r, METADATA_SELECT);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_MYSQL))
		ret = transport_mysql(session, r, METADATA_SELECT);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_ORACLE))
		ret = transport_oracle(session, r, METADATA_DELETE);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_TCP))
		ret = transport_socket(session, r, SOCKET_TYPE_TCP);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_UNIX))
		ret = transport_socket(session, r, SOCKET_TYPE_UNUX);

	if (session->auth_request) {
		if ((! strcmp(session->request_type, REQUEST_TYPE_JSON)) || (! strcmp(session->request_type, REQUEST_TYPE_MONGO)))
			bson_free(session->auth_request);
	}

	if (ret)
		return ret;

	// Process response (as per the configured request type)
	if (! strcmp(session->request_type, REQUEST_TYPE_JSON))
		ret = response_json(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_MONGO)) {
		ret = response_json(session, metadata, r);
		bson_free(session->auth_response);
		session->auth_response = NULL;
	}
	else if (! strcmp(session->request_type, REQUEST_TYPE_MYSQL))
		ret = response_mysql(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_ORACLE))
		ret = response_oracle(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_XML))
		ret = response_xml(session, metadata, r);

	if (session->auth_response)
		free(session->auth_response);

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
	else if (r->method & (NGX_HTTP_POST)) {
		// FIXME
	}
	else if (r->method & (NGX_HTTP_DELETE)) {
		// Delete the file
		if (unlink(metadata->path) < 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s unlink() error %s", metadata->file, metadata->path, strerror(errno));
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		// Delete metadata (only for MongoDB and SQL)
		// NB: we ignore errors here
		if (! strcmp(session->transport_type, TRANSPORT_TYPE_MONGO))
			// NB: Our MongoDB request was already prepared above for the AUTH step
			ret = transport_mongo(session, r, METADATA_DELETE);
		else if (! strcmp(session->transport_type, TRANSPORT_TYPE_MYSQL)) {
			// Switch query to DELETE one and rebuild it
			session->sql_query = from_ngx_str(r->pool, cdn_loc_conf->sql_delete);
			ret = transport_mysql(session, r, METADATA_DELETE);
		}
		else if (! strcmp(session->transport_type, TRANSPORT_TYPE_ORACLE)) {
			// Switch query to DELETE one and rebuild it
			session->sql_query = from_ngx_str(r->pool, cdn_loc_conf->sql_delete);
			ret = transport_oracle(session, r, METADATA_DELETE);
		}
	}

	// NB: The mapped file will be unmapped by the cleanup handler once data is sent to client
	return NGX_OK;
}

/**
 * Read file
 */
ngx_int_t read_fs(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	int fd, ret;
	ngx_http_cleanup_t *c;

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
		if ((c = ngx_pcalloc(r->pool, sizeof(ngx_http_cleanup_t))) == NULL) {
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
ngx_int_t send_file(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	int b1_len, b2_len;
	char *encoded = NULL;
	bool curl_encoded = false;
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
		// Lazy init curl, if not done so
		if (! session->curl)
			session->curl = curl_easy_init();
	
		if (session->curl) {
			encoded = curl_easy_escape(session->curl, metadata->filename, strlen(metadata->filename));
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
		if ((h = ngx_list_push(&r->headers_out.headers)) == NULL) {
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
	}

	// Clean up cURL - it might have been init'ed in transport_http, or just above, or never
	if (session->curl) {
		if (curl_encoded)
			curl_free(encoded);
		curl_easy_cleanup(session->curl);
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
		if ((b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t))) == NULL) {
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
void cleanup(metadata_t *metadata, ngx_http_request_t *r) {
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Running connection cleanup.");
	
	if (metadata->data && (munmap(metadata->data, metadata->length) < 0))
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s munmap() error %s", metadata->file, strerror(errno));
}

/**
 * Cleanup (unmap mapped file after serving)
 */
void ngx_http_cdn_cleanup(void *a) {
	ngx_http_request_t *r = (ngx_http_request_t *)a;
	metadata_t *metadata = ngx_http_get_module_ctx(r, ngx_http_cdn_module);
	cleanup(metadata, r);
}

/**
 * Extract authentication token
 */
ngx_int_t get_auth_token(session_t *session, ngx_http_request_t *r) {
	char *hdr_authorization;
	bool match = false;
	int i, j;
	ngx_int_t ret;
	ngx_str_t cookie_name, cookie_value;
	ngx_table_elt_t *h;
	ngx_list_part_t *part;

	// First, check Authorization header
	if (r->headers_in.authorization) {
		hdr_authorization = from_ngx_str(r->pool, r->headers_in.authorization->value);

		if (strstr(hdr_authorization, "Bearer")) {
			if ((session->auth_token = ngx_pcalloc(r->pool, strlen(hdr_authorization) + 1)) == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for Authorization header.", strlen(hdr_authorization) + 1);
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}

			strncpy(session->auth_token, hdr_authorization + 7, strlen(hdr_authorization) - 7);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Auth token found in Authorization header: %s", session->auth_token);
		}
	}

	// Next try a custom header, if defined
	if (strcmp(session->auth_header, DEFAULT_AUTH_HEADER)) {
		part = &r->headers_in.headers.part;
		for (i=0; i < r->headers_in.headers.nalloc; i++) {
			h = part->elts;
			for (j=0; j < part->nelts; j++) {
				if (! ngx_strncasecmp( h[j].key.data, (u_char *) session->auth_header, h[j].key.len)) {
					session->auth_token = from_ngx_str(r->pool, h[j].value);
					match = true;
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Auth token found in header %s: %s", session->auth_header, session->auth_token);
					break;
				}
			}

			if (match)
				break;

			part = part->next;
		}
	}

	// If cookie name given in config, try to find the cookie and to extract auth token from it
	if (strcmp(session->auth_cookie, DEFAULT_AUTH_COOKIE)) {
		cookie_name.len = strlen(session->auth_cookie);
		cookie_name.data = (u_char *) session->auth_cookie;

		ret = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &cookie_name, &cookie_value);
		if (ret == NGX_DECLINED) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Cookie %s for auth token not found", session->auth_cookie);
		}
		else {
			session->auth_token = from_ngx_str(r->pool, cookie_value);
		}
	}

	return NGX_OK;
}


/**
 * Check metdata for errors
 */
ngx_int_t metadata_check(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
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
		if ((metadata->filename = ngx_pcalloc(r->pool, strlen(metadata->file) + 1)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata filename.", strlen(metadata->file) + 1);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		strcpy(metadata->filename, metadata->file);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s filename not found, will use file ID %s", metadata->file, metadata->file);
	}

	// Check if we have the content type and use the default one if missing
	if (! metadata->content_type) {
		if ((metadata->content_type = ngx_pcalloc(r->pool, strlen(DEFAULT_CONTENT_TYPE) + 1)) == NULL) {
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
		if ((metadata->etag = ngx_pcalloc(r->pool, strlen(DEFAULT_ETAG) + 1)) == NULL) {
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
ngx_int_t get_path(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	int i, len, pos=0;

	len = strlen(session->fs_root) + 1 + 2 * session->fs_depth + strlen(metadata->file) + 1;
	if ((metadata->path = ngx_pcalloc(r->pool, len)) == NULL) {
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
ngx_int_t get_stat(metadata_t *metadata, ngx_http_request_t *r) {
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

