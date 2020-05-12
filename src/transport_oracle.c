/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "utils.h"

/**
 * Get file metadata from Oracle
 */
ngx_int_t transport_oracle(session_t *session, ngx_http_request_t *r, int mode) {
#ifdef CDN_ENABLE_ORACLE
	db_dsn_t dsn;
	ngx_int_t ret;

	// Parse DNS
	ret = parse_dsn(session, r, &dsn);
	if (ret)
		return ret;

	// Connect Oracle
	session->oracle_connection = OCI_ConnectionCreate(dsn.host, dsn.user, dsn.password, OCI_SESSION_DEFAULT);
	if (! session->oracle_connection) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to connect to Oracle: %s", OCI_ErrorGetString(OCI_GetLastError()));
		OCI_Cleanup();
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Create new statement
	session->oracle_statement = OCI_StatementCreate(session->oracle_connection);
	
	// Run the query
	OCI_ExecuteStmt(session->oracle_statement, session->sql_query);

	// Get result
	if (mode == METADATA_SELECT)
		session->oracle_result = OCI_GetResultset(session->oracle_statement);
#endif

	return NGX_OK;
}

