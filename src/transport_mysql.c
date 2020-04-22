#include "common.h"
#include "transport_sql.h"

/**
 * Helper: MySQL error handler
 */
static ngx_int_t close_mysql(MYSQL *conn, int ret) {
	mysql_close(conn);
	mysql_thread_end();
	return ret;
}

/**
 * Process MySQL response
 */
ngx_int_t transport_mysql(session_t *session, ngx_http_request_t *r) {
#ifdef CDN_ENABLE_MYSQL
	sql_dsn_t dsn;
	MYSQL conn;
	ngx_int_t ret;

	// Parse DNS
	ret = parse_dsn(session, r, &dsn);
	if (ret)
		return ret;

	// Init MySQL
	if (mysql_init(&conn) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to init MySQL.");
		return NGX_ERROR;
	}

	// Connect MySQL
	if (mysql_real_connect(&conn, dsn.host, dsn.user, dsn.password, dsn.db, dsn.port, dsn.socket, 0) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to connect to MySQL: %s", mysql_error(&conn));
		return close_mysql(&conn, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// Run the query
	if (mysql_query(&conn, session->sql_query)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to execute query %s: %s", session->sql_query, mysql_error(&conn));
		return close_mysql(&conn, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	if ((session->mysql_result = mysql_store_result(&conn)) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "MySQL result is NULL: %s", session->sql_query, mysql_error(&conn));
		return close_mysql(&conn, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	close_mysql(&conn, NGX_OK);
#endif

	return NGX_OK;
}

