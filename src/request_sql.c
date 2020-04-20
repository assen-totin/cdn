#include "common.h"

/**
 * Prepare SQL request
 */
ngx_int_t request_sql(session_t *session, ngx_http_request_t *r) {
	char *query;

	// session->sql_query now contains the query template, but we want if to have the expanded query, so swap it to a local variable
	query = session->sql_query;
	session->sql_query = ngx_pcalloc(r->pool, strlen(query) + strlen(session->jwt_value) + 1);
	if (query == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for query.", strlen(query) + strlen(session->jwt_value) + 1);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	sprintf(session->sql_query, query, session->jwt_value);

	return NGX_OK;
}

