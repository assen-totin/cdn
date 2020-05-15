/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "auth.h"
#include "murmur3.h"
#include "request.h"
#include "transport.h"
#include "utils.h"


/**
 * POST cleanup
 */
static void upload_cleanup(ngx_http_request_t *r, char *rb, bool rb_malloc, int status) {
	if (rb_malloc)
		free(rb);
	ngx_http_finalize_request(r, status);
}

/**
 * Read a line from current position
 */
static char *mpfd_get_line(ngx_http_request_t *r, char *begin) {
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
static char *mpfd_get_value(ngx_http_request_t *r, char *haystack, char *needle) {
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
 * Read the value from a header up to the first semicolon, if any
 */
static char *mpfd_get_header(ngx_http_request_t *r, char *line, char *header) {
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

/**
 * Read a chunk of data (form field value) into string
 */
static char *mpfd_get_field(ngx_http_request_t *r, char *rb, bool rb_malloc, char *from, int len) {
	char *ret;

	if ((ret = ngx_pcalloc(r->pool, len + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for upload field value.", len + 1);
		upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return NULL;
	}

	strncpy(ret, from, len);

	return ret;
}

/**
 * POST request body processing callback
 */
void cdn_handler_post (ngx_http_request_t *r) {
	off_t len = 0, len_buf;
	ngx_buf_t *b = NULL;
	ngx_chain_t *out, *bufs;
	ngx_int_t ret = NGX_OK;
	char *content_length_z, *content_type, *boundary, *line, *rb = NULL, *part = NULL;
	char *file_data_begin = NULL, *file_content_transfer_encoding = NULL;
	char *part_pos = NULL, *part_field_name = NULL, *part_filename = NULL, *part_content_type = NULL, *part_content_transfer_encoding = NULL, *part_end;
	char *curl_filename = NULL, *curl_content_type = NULL, *curl_content_disposition = NULL;
	int upload_content_type, file_fd, cnt_part = 0, cnt_header;
	long content_length, rb_pos = 0;
	uint64_t hash[2];
	bool rb_malloc = false;
	CURL *curl = NULL;
	session_t *session;
	metadata_t *metadata;

	// Check if we have body
	if (r->request_body == NULL)
		return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);

	// Init session
	if ((session = init_session(r)) == NULL)
		return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);

	// Init metadata
	if ((metadata = init_metadata(r)) == NULL)
		return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);

	// Reject in read-only mode
	if (! strcmp(session->read_only, "yes"))
		return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_BAD_REQUEST);

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload request body is ready for processing.");

	// Extract content type from header
	content_type = from_ngx_str(r->pool, r->headers_in.content_type->value);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload found header Content-Type: %s", content_type);
	if (strstr(content_type, CONTENT_TYPE_MPFD))
		upload_content_type = UPLOAD_CONTENT_TYPE_MPFD;
	else if (strstr(content_type, CONTENT_TYPE_AXWFU))
		upload_content_type = UPLOAD_CONTENT_TYPE_AXWFU;
	else {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Upload Content-Type %s not supported", content_type);
		return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// Extract content length from header
	content_length_z = from_ngx_str(r->pool, r->headers_in.content_length->value);
	if (! content_length_z) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Upload Content-Length not set");
		return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}
	content_length = atol(content_length_z);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload found header Content-Length: %l", content_length);

	// Use mmap or not?
	bufs = r->request_body->bufs;
	if (bufs && bufs->buf && bufs->buf->in_file) {
		// Use mmap from FD in the buffer
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload request body will use file buffers");
		len = bufs->buf->file_last;

		if ((rb = mmap(NULL, len, PROT_READ, MAP_SHARED, bufs->buf->file->fd, 0)) < 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Request body: mmap() error %s", strerror(errno));
			return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
		}
	}
	else {
		// Work from memory
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload request body will use memory buffers");

		rb = malloc(content_length);
		if (! rb) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to allocate %l bytes for request body conversion", content_length + 1);
			ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		}
		rb_malloc = true;

		for (bufs = r->request_body->bufs; bufs; bufs = bufs->next) {
			len_buf = ngx_buf_size(bufs->buf);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload request body: found new memory buffer with size: %l", len_buf);
			len += len_buf;

			memcpy(rb + rb_pos, bufs->buf->start, len_buf);
			rb_pos += len_buf;
		}
	}

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload request body: total memory buffer length: %l", len);
	if (len != content_length) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Upload request body mismatch: Content-Length %l, total memory buffers %l bytes", content_length, len);
		return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// Process multipart/form-data
	if (upload_content_type == UPLOAD_CONTENT_TYPE_MPFD) {
		// Extract boundary
		if ((boundary = mpfd_get_value(r, content_type, "boundary")) == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Upload request MPFD: unable to find boundary in Content-Type: %s", content_type);
			return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
		}

		// Loop around parts of the form
		part = rb;
		while (1) {
			part_field_name = NULL;
			part_filename = NULL;
			part_content_type = NULL;
			part_content_transfer_encoding = NULL;

			cnt_part++;
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload request MPFD: found new part %l", cnt_part);
			if (cnt_part > 10) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Upload request MPFD: too many loops while processing parts: %l", cnt_part);
				return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
			}

			// Seek a boundary and move past it + CRLF
			if (! (part_pos = memstr(part, boundary, rb - part + content_length))) {
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload request MPFD: boundary not found in body: %s", boundary);
				return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
			}

			// If next two characters are '--', this is the end of the form
			if (! memcmp(part_pos + strlen(boundary), "--", 2)) {
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Reached end of form");
				break;
			}

			part_pos += strlen(boundary) + 2;

			cnt_header = 0;
			while (1) {
				cnt_header++;
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload request MPFD: found new header %l in part %l", cnt_header, cnt_part);
				if (cnt_header > 10) {
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Upload request MPFD: too many loops while processing headers in part $l: %l", cnt_header, cnt_part);
					return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
				}

				// Get a line from the headers
				if ((line = mpfd_get_line(r, part_pos)) == NULL) {
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Failed to read a header line.");
					return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
				}

				// If line is empty, this is last line of the header; skip its CRLF and break
				if (strlen(line) == 0) {
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload request MPFD: found last line of header.");
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
			if ((part_end = memstr(part_pos, boundary, rb - part_pos + content_length)) == NULL) {
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload request MPFD: unable to find next boundary: %s", boundary);
				return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
			}
			part_end -= 4;	// Go back the "CRLF--" that preceed the boundary	
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload request MPFD: data length for part %l: %l", cnt_part, part_end - part_pos);

			// If this is a file part, remember data begin and end
			if (part_filename) {
				metadata->filename = part_filename;
				if (! metadata->content_type)
					metadata->content_type = part_content_type;
				file_content_transfer_encoding = part_content_transfer_encoding;
				file_data_begin = part_pos;
				metadata->length = part_end - part_pos;
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload request MPFD: filename %s size %l", metadata->filename, metadata->length);
			}

			// Check if field name is file data
			else if (! strcmp(part_field_name, "d")) {
				file_data_begin = part_pos;
				metadata->length = part_end - part_pos;
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload request MPFD: raw data size %l", metadata->length);
			}

			// Check if field name is a file name
			else if (! strcmp(part_field_name, "n"))
				metadata->filename = mpfd_get_field(r, rb, rb_malloc, part_pos, part_end - part_pos);

			// Check if field name is content type
			else if (! strcmp(part_field_name, "ct"))
				metadata->content_type = mpfd_get_field(r, rb, rb_malloc, part_pos, part_end - part_pos);

			// Check if field name is content disposition
			else if (! strcmp(part_field_name, "cd"))
				metadata->content_disposition = mpfd_get_field(r, rb, rb_malloc, part_pos, part_end - part_pos);

			// Move the part forward
			part = part_end;
		}

		// If we did not find a file, bail out
		if (! file_data_begin) {
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload request MPFD: unable to find uploaded file");
			return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
		}

		// FIXME: Decode file if needed?
		if (file_content_transfer_encoding) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Upload request: content transfer encoding %s not supported (yet)", file_content_transfer_encoding);
			return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
		}
	}

	// Process application/x-www-form-urlencoded
	else if (upload_content_type == UPLOAD_CONTENT_TYPE_AXWFU) {
		// Init CURL
		curl = curl_easy_init();

		// Traverse the request body
		part = rb;
		while(part) {
			// Find next =
			char *part_end;
			if ((part_pos = memchr(part, '=', rb - part + content_length)) == NULL) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Upload request AXWFU: could not find next key-value delimiter");
				return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
			}
			part_end = part_pos;
			
			// Extract form field name
			if ((part_field_name = ngx_pcalloc(r->pool, part_end - part + 1)) == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for for field name.", part_end - part + 1);
				return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
			}
			strncpy(part_field_name, part, part_end - part);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload request AXWFU: found field name %s", part_field_name);

			// Jump over the =
			part_pos ++;

			// Find next &
			if ((part = memchr(part, '&', rb - part_pos + content_length)) == NULL) {
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload request AXWFU: reached last form field");
				part_end = rb + content_length;
			}
			else {
				part_end = part;

				// Jump over the &
				part ++;
			}

			// Extract form field value
			char *form_field_value;
			if ((form_field_value = ngx_pcalloc(r->pool, part_end - part_pos + 1)) == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for for field name.", part_end - part_pos + 1);
				return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
			}
			strncpy(form_field_value, part_pos, part_end - part_pos);

			// URL decode the value
			int form_field_value_len;
			char *form_field_value_decoded = curl_easy_unescape(curl, form_field_value, 0, &form_field_value_len);
			if (form_field_value_len < 1024) {
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload request AXWFU: field name %s value %s", part_field_name, form_field_value_decoded);
			}
			else {
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Upload request AXWFU: field name %s value is %l bytes", part_field_name, form_field_value_len);
			}

			// Decide what to do with the field
			if (! strcmp(part_field_name, "d")) {
				file_data_begin = form_field_value_decoded;
				metadata->length = form_field_value_len;
			}
			else if (! strcmp(part_field_name, "n"))
				curl_filename = form_field_value_decoded;
			else if (! strcmp(part_field_name, "ct"))
				curl_content_type = form_field_value_decoded;
			else if (! strcmp(part_field_name, "cd"))
				curl_content_disposition = form_field_value_decoded;
		}	
	}

	// Create hash salt: No of seconds for today with ms precision, mulitplied by server id =< 49
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int sec = tv.tv_sec % 86400;
    int msec = tv.tv_usec / 1000;
    uint32_t salt = session->server_id * (1000 * sec + msec);

	// Create file hash
	murmur3((void *)file_data_begin, metadata->length, salt, (void *) &hash[0]);

	// Convert hash to hex string
	if ((metadata->file = ngx_pcalloc(r->pool, 33)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate 33 bytes for file ID.");
		return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}
	sprintf(metadata->file, "%016lx%016lx", hash[0], hash[1]);

	// Try to find an authorisation token
	if ((ret = get_auth_token(session, r)) > 0)
		return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);

	// Extract authentication token to value
	if (! strcmp(session->auth_type, AUTH_TYPE_JWT)) {
		if ((ret = auth_jwt(session, r)) > 0)
			return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}
	else if (! strcmp(session->auth_type, AUTH_TYPE_SESSION)) {
		if ((ret = auth_session(session, r)) > 0)
			return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// Metadata: merge of defaults if some values are missing: filename
	if (! metadata->filename) {
		if (curl_filename)
			metadata->filename = curl_filename;
		else {
			if ((metadata->filename = ngx_pcalloc(r->pool, strlen(DEFAULT_FILE_NAME) + 1)) == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata filename.", strlen(DEFAULT_FILE_NAME) + 1);
				return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
			}
			strcpy(metadata->filename, DEFAULT_FILE_NAME);
		}
	}

	// Metadata: merge of defaults if some values are missing: content_type
	if (! metadata->content_type) {
		if (curl_content_type)
			metadata->content_type = curl_content_type;
		else {
			if ((metadata->content_type = ngx_pcalloc(r->pool, strlen(DEFAULT_CONTENT_TYPE) + 1)) == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata content_type.", strlen(DEFAULT_CONTENT_TYPE) + 1);
				return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
			}
			strcpy(metadata->content_type, DEFAULT_CONTENT_TYPE);
		}
	}

	// Metadata: merge of defaults if some values are missing: content_disposition
	if (! metadata->content_disposition) {
		if (curl_content_disposition)
			metadata->content_disposition = curl_content_disposition;
		else {
			if ((metadata->content_disposition = ngx_pcalloc(r->pool, strlen(DEFAULT_CONTENT_DISPOSITION) + 1)) == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata content_disposition.", strlen(DEFAULT_CONTENT_DISPOSITION) + 1);
				return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
			}
			strcpy(metadata->content_disposition, DEFAULT_CONTENT_DISPOSITION);
		}
	}

	// Metadata: set upload_date
	metadata->upload_date = time(NULL);

	// Metadata: set etag to the file ID
	metadata->etag = metadata->file;

	// Prepare metadata request (as per the configured request type)
	if (! strcmp(session->request_type, REQUEST_TYPE_JSON))
		ret = request_post_json(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_MONGO))
		ret = request_post_mongo(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_MYSQL))
		ret = request_post_sql(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_ORACLE))
		ret = request_post_sql(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_POSTGRESQL))
		ret = request_post_sql(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_XML))
		ret = request_post_xml(session, metadata, r);

	if (ret)
		return upload_cleanup(r, rb, rb_malloc, ret);

	// Query for metadata based on transport
	if (! strcmp(session->transport_type, TRANSPORT_TYPE_HTTP))
		ret = transport_http(session, r);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_INTERNAL))
		ret = transport_internal(session, metadata, r, METADATA_INSERT);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_MONGO))
		ret = transport_mongo(session, r, METADATA_INSERT);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_MYSQL))
		ret = transport_mysql(session, r, METADATA_INSERT);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_ORACLE))
		ret = transport_oracle(session, r, METADATA_INSERT);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_POSTGRESQL))
		ret = transport_postgresql(session, r, METADATA_INSERT);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_TCP))
		ret = transport_socket(session, r, SOCKET_TYPE_TCP);
	else if (! strcmp(session->transport_type, TRANSPORT_TYPE_UNIX))
		ret = transport_socket(session, r, SOCKET_TYPE_UNUX);

	if (session->auth_request) {
		if ((! strcmp(session->request_type, REQUEST_TYPE_JSON)) || (! strcmp(session->request_type, REQUEST_TYPE_MONGO)))
			bson_free(session->auth_request);
	}

	if (ret)
		return upload_cleanup(r, rb, rb_malloc, ret);

	// Process metadata response (as per the configured request type)
	if (! strcmp(session->request_type, REQUEST_TYPE_JSON))
		ret = response_post_json(session, metadata, r);
	else if (! strcmp(session->request_type, REQUEST_TYPE_MONGO)) {
		metadata->status = NGX_HTTP_OK;
		ret = NGX_OK;
	}
	else if (! strcmp(session->request_type, REQUEST_TYPE_MYSQL)) {
		metadata->status = NGX_HTTP_OK;
		ret = NGX_OK;
	}
	else if (! strcmp(session->request_type, REQUEST_TYPE_ORACLE)) {
		metadata->status = NGX_HTTP_OK;
		ret = NGX_OK;
	}
	else if (! strcmp(session->request_type, REQUEST_TYPE_POSTGRESQL)) {
		metadata->status = NGX_HTTP_OK;
		ret = NGX_OK;
	}
	else if (! strcmp(session->request_type, REQUEST_TYPE_XML))
		ret = response_post_xml(session, metadata, r);

	if (session->auth_response)
		free(session->auth_response);

	if (ret)
		return upload_cleanup(r, rb, rb_malloc, ret);

	if (metadata->status != NGX_HTTP_OK)
		return upload_cleanup(r, rb, rb_malloc, metadata->status);

	// Clean up CURL if it got used
	if (curl) {
		if (curl_filename)
			curl_free(curl_filename);
		if (curl_content_type)
			curl_free(curl_content_type);
		if (curl_content_disposition)
			curl_free(curl_content_disposition);
		curl_easy_cleanup(session->curl);
	}

	// Obtain file path
	if (get_path(session, metadata, r) > 0)
		return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);

	// Save file to CDN
	if ((file_fd = open(metadata->path, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP)) == -1) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Upload request: failed to create file %s: %s", metadata->path, strerror(errno));
		return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}
	if (write(file_fd, (const void *)file_data_begin, metadata->length) < metadata->length) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Upload request: failed to write %l bytes to file %s: %s", metadata->length, metadata->path, strerror(errno));
		close(file_fd);
		return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}
	close(file_fd);

	// Prepare output chain
	out = ngx_alloc_chain_link(r->pool);
	if (out == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for buffer chain.", sizeof(ngx_chain_t));
		return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// Prepare output buffer
	if ((b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t))) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for respone buffer.", sizeof(ngx_buf_t));
		return upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// Clean up
	if (rb_malloc)
		free(rb);

	// Prepare output chain; hook the buffer
	out->buf = b;
	out->next = NULL; 

	// Set the buffer
	b->pos = (u_char *) metadata->file;
	b->last = (u_char *) metadata->file + strlen(metadata->file);
	b->mmap = 1; 
	b->last_buf = 1; 

	// Status
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = b->last - b->pos;

	// Content-Type 
	r->headers_out.content_type.len = strlen(CONTENT_TYPE_TEXT_PLAIN);
	r->headers_out.content_type.data = (u_char*) CONTENT_TYPE_TEXT_PLAIN;

	ret = ngx_http_send_header(r);
	ret = ngx_http_output_filter(r, out);
	ngx_http_finalize_request(r, ret);
}

