#include "common.h"
#include "utils.h"

/**
 * OPTIONS request handler
 */
ngx_int_t ngx_http_cdn_options_handler (ngx_http_request_t *r, ngx_str_t cors_origin) {
	char *cors_origin_z;
	ngx_table_elt_t *h;

	// Add Access-Control-Allow-Origin header
	cors_origin_z = from_ngx_str(r->pool, cors_origin);
	if ((h = ngx_list_push(&r->headers_out.headers)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to add new output header: %s.", HEADER_ACCESS_CONTROL_ALLOW_ORIGIN);
		return NGX_ERROR;
	}
	h->hash = 1;
	ngx_str_set(&h->key, HEADER_ACCESS_CONTROL_ALLOW_ORIGIN);
	ngx_str_set(&h->value, cors_origin_z);

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

