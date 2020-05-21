/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"

/**
 * Filter: tokenise by char and return particular token
 */
char *filter_token(ngx_http_request_t *r, char *string, char *delimiter, int pos) {
	int i;
	char *ret, *prev, *next;

	if (! string)
		return NULL;

	if (! delimiter || ! pos)
		return string;

	prev = string;
	next = string + strlen(string);
	for (i=0; i < pos; i++) {
		if (i > 0)
			prev = next + 1;
		next = strstr(prev, delimiter);
		if (! next) {
			// If last loop, go to last char of string; else return "not found"
			if (i == (pos - 1))
				next = string + strlen(string);
			else
				return NULL;
		}
	}

	if ((ret = ngx_pcalloc(r->pool, next - prev + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for filter_token.", next - prev + 1);
		return NULL;
	}

	memcpy(ret, prev, next - prev);
	ret[next - prev] = '\0';

	// If the delimiter was last character of the string, return NULL instead of empty string
	if (! strlen(ret))
		return NULL;

	return ret;
}

/**
 * Apply the chosen filter to auth_value
 */
ngx_int_t filter_auth_value(session_t *session, ngx_http_request_t *r) {
	char *filter_name;

	// If no filter set, return
	if (! strcmp(session->auth_filter, DEFAULT_AUTH_FILTER))
		return NGX_OK; 

	// Extract filter name using our own tokeniser: first of comma-separated list
	filter_name = filter_token(r, session->auth_filter, ",", 1);

	// Apply filter token
	if (! strcmp(filter_name, "filter_token")) {
		// Extract the delimiter and position
		char *delimiter = filter_token(r, session->auth_filter, ",", 2);
		int pos = atoi(filter_token(r, session->auth_filter, ",", 3));

		// Apply filter
		session->auth_value = filter_token(r, session->auth_value, delimiter, pos);
	}
	else {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Unknown filter specified: %s", filter_name);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	return NGX_OK; 
}

