/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "utils.h"

/**
 * Helper: MySQL error handler
 */
static ngx_int_t close_mysql(MYSQL *conn, ngx_int_t ret) {
#ifdef CDN_ENABLE_MYSQL
	mysql_close(conn);
	mysql_thread_end();
#endif
	return ret;
}

/**
 * Get file metadata from MySQL
 */
ngx_int_t transport_mysql(session_t *session, ngx_http_request_t *r, int mode) {
#ifdef CDN_ENABLE_MYSQL
	MYSQL conn;
	ngx_int_t ret;

	// Parse DNS
	if ((ret = parse_dsn(session, r)) > 0)
		return ret;

	// Init MySQL
	if (mysql_init(&conn) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to init MySQL.");
		return NGX_ERROR;
	}

	// Connect MySQL
	if (mysql_real_connect(&conn, session->dsn->host, session->dsn->user, session->dsn->password, session->dsn->db, session->dsn->port, session->dsn->socket, 0) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to connect to MySQL: %s", mysql_error(&conn));
		return close_mysql(&conn, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// Run the query
ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, session->sql_query);
	if (mysql_query(&conn, session->sql_query)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to execute query %s: %s", session->sql_query, mysql_error(&conn));
		return close_mysql(&conn, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// Only fetch result when querying for data
	if (mode == METADATA_SELECT) {
		if ((session->mysql_result = mysql_store_result(&conn)) == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "MySQL result is NULL: %s", session->sql_query, mysql_error(&conn));
			return close_mysql(&conn, NGX_HTTP_INTERNAL_SERVER_ERROR);
		}
	}

	close_mysql(&conn, NGX_OK);
#endif

	return NGX_OK;
}

