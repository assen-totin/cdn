/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"

/**
 * Prepare SQL request for GET
 */
ngx_int_t request_get_sql(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	char *query;

	// session->sql_query now contains the query template, but we want if to have the expanded query, so swap it to a local variable
	query = session->sql_query;
	if ((session->sql_query = ngx_pcalloc(r->pool, strlen(query) + strlen(session->auth_value) + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for query.", strlen(query) + strlen(session->auth_value) + 1);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	sprintf(session->sql_query, query, metadata->file, session->auth_value);

	return NGX_OK;
}

/**
 * Prepare SQL request for POST
 */
ngx_int_t request_post_sql(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	char *query;

	// session->sql_query now contains the query template, but we want if to have the expanded query, so swap it to a local variable
	query = session->sql_query;
	if ((session->sql_query = ngx_pcalloc(r->pool, strlen(query) + strlen(session->auth_value) + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for query.", strlen(query) + strlen(session->auth_value) + 1);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	sprintf(session->sql_query, query, session->auth_value, metadata->file, metadata->filename, metadata->length, metadata->content_type, metadata->content_disposition, metadata->upload_date, metadata->etag);

	return NGX_OK;
}

