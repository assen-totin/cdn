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
	//char *acah;
	ngx_table_elt_t *h;
	session_t *session;

	// Init session
	if ((session = init_session(r)) == NULL)
		return NGX_ERROR;

	// Add Access-Control-Allow-Origin header
ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "%s: %s", HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, session->cors_origin);
	if ((h = ngx_list_push(&r->headers_out.headers)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to add new output header: %s.", HEADER_ACCESS_CONTROL_ALLOW_ORIGIN);
		return NGX_ERROR;
	}
	h->hash = 1;
	ngx_str_set(&h->key, HEADER_ACCESS_CONTROL_ALLOW_ORIGIN);
//	ngx_str_set(&h->value, session->cors_origin);
	h->value.len = strlen(session->cors_origin);
	h->value.data = (u_char*)session->cors_origin;

	// Add Access-Control-Allow-Methods header
ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "%s: %s", HEADER_ACCESS_CONTROL_ALLOW_METHODS, DEFAULT_ACCESS_CONTROL_ALLOW_METHODS);
	if ((h = ngx_list_push(&r->headers_out.headers)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to add new output header: %s.", HEADER_ACCESS_CONTROL_ALLOW_METHODS);
		return NGX_ERROR;
	}
	h->hash = 1;
	ngx_str_set(&h->key, HEADER_ACCESS_CONTROL_ALLOW_METHODS);
	ngx_str_set(&h->value, DEFAULT_ACCESS_CONTROL_ALLOW_METHODS);

ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "BEFORE ACAH");

	// Add Access-Control-Allow-Headers header + the custom value, if any
	if ((h = ngx_list_push(&r->headers_out.headers)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to add new output header: %s.", HEADER_ACCESS_CONTROL_ALLOW_HEADERS);
		return NGX_ERROR;
	}
	h->hash = 1;
	ngx_str_set(&h->key, HEADER_ACCESS_CONTROL_ALLOW_HEADERS);

ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "ACAH ALLOCATED");

//	h->value.len = strlen(acah);
//	h->value.data = (u_char*)acah;

	if ((h->value.data = ngx_pcalloc(r->pool, sizeof(DEFAULT_ACCESS_CONTROL_ALLOW_HEADERS) + 2 + strlen(session->auth_header) + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for Access-Control-Allow-Headers.", sizeof(DEFAULT_ACCESS_CONTROL_ALLOW_HEADERS) + 2 + strlen(session->auth_header) + 1);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "DATA ALLOCATED");

	if (strcmp(session->auth_header, DEFAULT_AUTH_HEADER)) {
ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "%s: %s, %s", HEADER_ACCESS_CONTROL_ALLOW_HEADERS, DEFAULT_ACCESS_CONTROL_ALLOW_HEADERS, session->auth_header);
		sprintf(h->value.data, "%s, %s", DEFAULT_ACCESS_CONTROL_ALLOW_HEADERS, session->auth_header);
	}
	else {
ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "%s: %s", HEADER_ACCESS_CONTROL_ALLOW_HEADERS, DEFAULT_ACCESS_CONTROL_ALLOW_HEADERS);
		sprintf(h->value.data, "%s", DEFAULT_ACCESS_CONTROL_ALLOW_HEADERS);
	}

	h->value.len = strlen(h->value.data);

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

