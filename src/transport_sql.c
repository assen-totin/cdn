#include "common.h"

/**
 * Helper: SQL DSN parser
 */
static inline ngx_int_t property_sql(ngx_http_request_t *r, char **field, char *field_name, char *value) {
	char *f;

	f = ngx_pcalloc(r->pool, strlen(value) + 1);
	if (f == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for MySQL property %s: %s.", strlen(value) + 1, field_name, value);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	strcpy(f, value);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found MySQL property %s: %s", field_name, f);

	return NGX_OK;
}

/**
 * SQL DSN parser
 */
ngx_int_t parse_dsn(session_t *session, ngx_http_request_t *r, sql_dsn_t *dsn) {
	int i;
	char *token, *saveptr, *str;
	ngx_int_t ret;

	// Init
	dsn->host = NULL;
	dsn->port_str = NULL;
	dsn->port = 0;
	dsn->socket = NULL;
	dsn->user = NULL;
	dsn->password = NULL;
	dsn->db = NULL;

	// host:port|socket:user:password:db
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing MySQL DSN: %s", session->sql_dsn);
	for (str = session->sql_dsn, i = 0; ; str = NULL, i++) {
		token = strtok_r(str, ":", &saveptr);
		if (token == NULL)
			break;

		switch(i) {
			case 0:
				if ((ret = property_sql(r, &dsn->host, "host", token)) > 0)
					return ret;
				break;
			case 1:
				if ((ret = property_sql(r, &dsn->port_str, "port_str", token)) > 0)
					return ret;
				break;
			case 2:
				if ((ret = property_sql(r, &dsn->user, "user", token)) > 0)
					return ret;
				break;
			case 3:
				if ((ret = property_sql(r, &dsn->password, "password", token)) > 0)
					return ret;
				break;
			case 4:
				if ((ret = property_sql(r, &dsn->db, "db", token)) > 0)
					return ret;
				break;
		}

        printf("%s\n", token);
    }

	// Detect if we were given a port or a socket
	dsn->port = atoi(dsn->port_str);
	if (dsn->port == 0)
		dsn->socket = dsn->port_str;

	return NGX_OK;
}

