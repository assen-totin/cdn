/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "utils.h"

/**
 * Helper: Oracle error handler
 */
static ngx_int_t close_oracle(session_t *session, ngx_int_t ret) {
#ifdef CDN_ENABLE_ORACLE
	if (session->oracle_statement)
		OCI_StatementFree(session->oracle_statement);
	if (session->oracle_connection)
		OCI_ConnectionFree(session->oracle_connection);
#endif
	return ret;
}

/**
 * Get/Put/Delete file metadata from Oracle
 */
ngx_int_t transport_oracle(session_t *session, ngx_http_request_t *r, int mode) {
#ifdef CDN_ENABLE_ORACLE
	ngx_int_t ret;

	// Parse DNS
	if ((ret = parse_dsn(session, r)) > 0)
		return ret;

	// Connect Oracle
	session->oracle_connection = OCI_ConnectionCreate(session->dsn->host, session->dsn->user, session->dsn->password, OCI_SESSION_DEFAULT);
	if (! session->oracle_connection) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to connect to Oracle: %s", OCI_ErrorGetString(OCI_GetLastError()));
		return close_oracle(session, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// Create new statement
	if ((session->oracle_statement = OCI_StatementCreate(session->oracle_connection)) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to create new Oracle statement: %s", OCI_ErrorGetString(OCI_GetLastError()));
		return close_oracle(session, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}
	
	// Run the query
	if (! OCI_ExecuteStmt(session->oracle_statement, session->sql_query)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to execute Oracle statement: %s", OCI_ErrorGetString(OCI_GetLastError()));
		return close_oracle(session, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// Get result
	if (mode == METADATA_SELECT) {
		if ((session->oracle_result = OCI_GetResultset(session->oracle_statement)) == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to fetch resultset from Oracle: %s", OCI_ErrorGetString(OCI_GetLastError()));
			return close_oracle(session, NGX_HTTP_INTERNAL_SERVER_ERROR);
		}
	}
	else {
		// Put, Delete
		if (! OCI_API OCI_Commit (session->oracle_connection)) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to commit to Oracle: %s", OCI_ErrorGetString(OCI_GetLastError()));
			return close_oracle(session, NGX_HTTP_INTERNAL_SERVER_ERROR);
		}

		// Try to get any result for INSERT
		if (mode == METADATA_INSERT) {
			session->oracle_result = OCI_GetResultset(session->oracle_statement);
	}
#endif

	return NGX_OK;
}

