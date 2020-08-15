/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"

/**
 * Prepare SQL request for GET
 */
ngx_int_t request_get_sql(session_t *session, metadata_t *metadata, ngx_http_request_t *r, int mode) {
	char *query;
	int len;

	// session->sql_query now contains the query template, but we want if to have the expanded query, so swap it to a local variable
	query = session->sql_query;

	// Calculate length for query template + data (this will leave some small overhead from placeholders)
	len = strlen(session->sql_query);
	len += strlen(metadata->file);
	if (session->auth_value)
		len += strlen(session->auth_value);

	if ((session->sql_query = ngx_pcalloc(r->pool, len + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for query.", len + 1);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (mode == METADATA_SELECT) {
		if (session->auth_value)
			sprintf(session->sql_query, query, metadata->file, session->auth_value);
		else
			sprintf(session->sql_query, query, metadata->file, "");
	}
	else if (mode == METADATA_DELETE)
		sprintf(session->sql_query, query, metadata->file);

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "SQL to run: %s", session->sql_query);

	return NGX_OK;
}

/**
 * Prepare SQL request for POST
 */
ngx_int_t request_post_sql(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	char *query;
	int len = 0;

	// session->sql_query now contains the query template, but we want if to have the expanded query, so swap it to a local variable
	query = session->sql_query;

	// Calculate length for query template + data (this will leave some small overhead from placeholders)
	len = strlen(session->sql_query);
	len += strlen(metadata->file);
	len += strlen(metadata->filename);
	len += 10;
	len += strlen(metadata->content_type);
	len += strlen(metadata->content_disposition);
	len += 10;
	len += strlen(metadata->etag);
	if (session->auth_value)
		len += strlen(session->auth_value);

	if ((session->sql_query = ngx_pcalloc(r->pool, len + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for query.", len + 1);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (session->auth_value)
		sprintf(session->sql_query, query, session->auth_value, metadata->file, metadata->filename, metadata->content_type, metadata->content_disposition, metadata->etag);
	else
		sprintf(session->sql_query, query, "", metadata->file, metadata->filename, metadata->content_type, metadata->content_disposition, metadata->etag);

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "SQL to run: %s", session->sql_query);

	return NGX_OK;
}

