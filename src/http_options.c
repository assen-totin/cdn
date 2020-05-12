/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "utils.h"

/**
 * OPTIONS request handler
 */
ngx_int_t cdn_handler_options (ngx_http_request_t *r) {
	ngx_table_elt_t *h;
	session_t *session;

	// Init session
	if ((session = init_session(r)) == NULL)
		return NGX_ERROR;

	// Add Access-Control-Allow-Origin header
	if ((h = ngx_list_push(&r->headers_out.headers)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to add new output header: %s.", HEADER_ACCESS_CONTROL_ALLOW_ORIGIN);
		return NGX_ERROR;
	}
	h->hash = 1;
	ngx_str_set(&h->key, HEADER_ACCESS_CONTROL_ALLOW_ORIGIN);
	ngx_str_set(&h->value, session->cors_origin);

	// Add Access-Control-Allow-Methods header
	if ((h = ngx_list_push(&r->headers_out.headers)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to add new output header: %s.", HEADER_ACCESS_CONTROL_ALLOW_METHODS);
		return NGX_ERROR;
	}
	h->hash = 1;
	ngx_str_set(&h->key, HEADER_ACCESS_CONTROL_ALLOW_METHODS);
	ngx_str_set(&h->value, DEFAULT_ACCESS_CONTROL_ALLOW_METHODS);

	// Add Access-Control-Allow-Headers header
	if ((h = ngx_list_push(&r->headers_out.headers)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to add new output header: %s.", HEADER_ACCESS_CONTROL_ALLOW_HEADERS);
		return NGX_ERROR;
	}
	h->hash = 1;
	ngx_str_set(&h->key, HEADER_ACCESS_CONTROL_ALLOW_HEADERS);
	ngx_str_set(&h->value, DEFAULT_ACCESS_CONTROL_ALLOW_HEADERS);

	// There will be no body
	r->header_only = 1;
	r->allow_ranges = 0;

	// Status
	r->headers_out.status = NGX_HTTP_OK;

	// Content-Length
	r->headers_out.content_length_n = 0;

	// Send headers
	return ngx_http_send_header(r);
}

