/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "utils.h"

/**
 * Helper: postgresql error handler
 */
static ngx_int_t close_postgresql(session_t *session, ngx_int_t ret) {
#ifdef CDN_ENABLE_POSTGRESQL
	if (session->postgresql_result)
		PQclear(session->postgresql_result);

	if (session->postgresql_connection)
		PQfinish(session->postgresql_connection);
#endif
	return ret;
}

/**
 * Get/Put/Delete file metadata from postgresql
 */
ngx_int_t transport_postgresql(session_t *session, ngx_http_request_t *r, int mode) {
#ifdef CDN_ENABLE_POSTGRESQL
	session->postgresql_connection = NULL;
	session->postgresql_result = NULL;

	// Connect postgresql
	session->postgresql_connection = PQconnectdb(session->db_dsn);
	if (PQstatus(session->postgresql_connection) != CONNECTION_OK) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to connect to postgresql: %s", PQerrorMessage(session->postgresql_connection));
		return close_postgresql(session, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// Run the query
	session->postgresql_result = PQexec(session->postgresql_connection, session->sql_query);
	if ((PQresultStatus(session->postgresql_result) != PGRES_COMMAND_OK) && (PQresultStatus(session->postgresql_result) != PGRES_TUPLES_OK)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to execute query %s: %s", session->sql_query, PQerrorMessage(session->postgresql_connection));
		return close_postgresql(session, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// If deleting, clear query and disconnect; for getting and putting, we'll clean up in the request processing function
	if (mode == METADATA_DELETE) {
		PQclear(session->postgresql_result);
		PQfinish(session->postgresql_connection);
		session->postgresql_connection = NULL;
		session->postgresql_result = NULL;
	}
#endif

	return NGX_OK;
}

