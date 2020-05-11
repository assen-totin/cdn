#include "common.h"
#include "utils.h"

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
 * Read the value from a header up to the first semicolon, if any
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

/**
 * POST cleanup
 */
void upload_cleanup(ngx_http_request_t *r, char *rb, bool rb_malloc, int status) {
	if (rb_malloc)
		free(rb);
	ngx_http_finalize_request(r, status);
}

/**
 * Read a chunk of data (form field value) into string
 */
char *mpfd_get_field(ngx_http_request_t *r, char *rb, bool rb_malloc, char *from, int len) {
	char *ret;

	if ((ret = ngx_pcalloc(r->pool, len + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for upload field value.", len + 1);
		upload_cleanup(r, rb, rb_malloc, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return NULL;
	}

	strncpy(ret, from, len + 1);

	return ret;
}


