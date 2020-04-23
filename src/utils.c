#include "common.h"

/**
 * Helper: convert Nginx string to normal
 */
char *from_ngx_str(ngx_pool_t *pool, ngx_str_t ngx_str) {
		if (! ngx_str.len)
			return NULL;

		char *ret = ngx_pcalloc(pool, ngx_str.len + 1);
		if (ret == NULL) {
			ngx_log_error(NGX_LOG_EMERG, pool->log, 0, "Failed to allocate %l bytes in from_ngx_str().", ngx_str.len + 1);
			return NULL;
		}
		memcpy(ret, ngx_str.data, ngx_str.len);
		return ret;
}

/**
 * Helper: Set metadata field from char value
 */
ngx_int_t set_metadata_field (ngx_http_request_t *r, char **field, char *field_name, const char *value) {
	char *f;

	if (value) {
		if ((f = ngx_pcalloc(r->pool, strlen(value) + 1)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata %s.", field_name, strlen(value) + 1);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		strcpy(f, value);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata %s: %s", field_name, f);
	}
	else {
		if ((f = ngx_pcalloc(r->pool, 1)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata %s.", field_name, 1);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		sprintf(f, "%s", "");
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata %s: empty value", field_name);
	}

	*field = f;

	return NGX_OK;
}

/**
 * Store a header
 */
static inline ngx_int_t store_header(session_t *session, ngx_http_request_t *r, ngx_str_t name, ngx_str_t value) {
	cdn_kvp_t *headers;

	// NB: Nginx pool does not have realloc, so we need to emulate it
	//TODO: Maybe allocate bigger blocks to avoid doing a realloc on each new header?

	// Always allocate memory
	headers = ngx_pnalloc(r->pool, sizeof(cdn_kvp_t) * (session->headers_count + 1));
	if (headers == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for %l headers KVP.", sizeof(cdn_kvp_t) * (session->headers_count + 1), session->headers_count + 1);
		return NGX_ERROR;
	}

	// If we have previous values, copy them
	if (session->headers_count)
		memcpy(headers, session->headers, sizeof(cdn_kvp_t) * session->headers_count);
	session->headers = headers;

	// Extract header name
	session->headers[session->headers_count].name = from_ngx_str(r->pool, name);

	// Extract header value
	session->headers[session->headers_count].value = from_ngx_str(r->pool, value);

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found header %s: %s", session->headers[session->headers_count].name, session->headers[session->headers_count].value);

	session->headers_count ++;

	return NGX_OK;
}

/**
 * Extract all headers
 */
ngx_int_t get_all_headers(session_t *session, ngx_http_request_t *r) {
	int i, j;
	ngx_table_elt_t *h;
	ngx_list_part_t *part;

	part = &r->headers_in.headers.part;
	for (i=0; i < r->headers_in.headers.nalloc; i++) {
		h = part->elts;
		for (j=0; j < part->nelts; j++)
			store_header(session, r, h[j].key, h[j].value);

		part = part->next;
	}

	return NGX_OK;
}

/**
 * Extract all cookies from headers
 */
ngx_int_t get_all_cookies(session_t *session, ngx_http_request_t *r) {
	int i, j, cookie_index = -1;
	char *s0, *s1, *s2;
	char *str1, *str2, *token, *subtoken, *saveptr1, *saveptr2;
	char *cookie_delim = " ", *cookie_subdelim = "=";
	ngx_table_elt_t **elts;
	cdn_kvp_t *cookies;

	if (! r->headers_in.cookies.nelts) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "No cookies found");
		return NGX_OK;
	}

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found a total of %l Cookie header", r->headers_in.cookies.nelts);
	elts = r->headers_in.cookies.elts;
	session->cookies_count = r->headers_in.cookies.nelts;

	// Allocate initial memory we have at least r->headers_in.cookies.nelts, but may be more)
	session->cookies = ngx_pnalloc(r->pool, sizeof(cdn_kvp_t) * r->headers_in.cookies.nelts);
	if (session->cookies == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for %l cookies KVP.", sizeof(cdn_kvp_t) * r->headers_in.cookies.nelts, r->headers_in.cookies.nelts);
		return NGX_ERROR;
	}

	for (i=0; i<r->headers_in.cookies.nelts; i++) {
		s0 = from_ngx_str(r->pool, elts[i]->value);
		for (str1 = s0; ; str1 = NULL) {
			token = strtok_r(str1, cookie_delim, &saveptr1);
			if (token == NULL)
				break;

			s1 = strchr(token, ';');
			if (s1 == token + strlen(token) - 1) {
				s2 = ngx_pcalloc(r->pool, strlen(token));
				if (s2 == NULL) {
					ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for cookie token.", strlen(token));
					return NGX_ERROR;
				}
				strncpy(s2, token, strlen(token) - 1);
			}
			else
				s2 = token;

			// Check to see if we have space to accommodate the cookie
			cookie_index ++;
			if (cookie_index == session->cookies_count) {
				cookies = ngx_pnalloc(r->pool, sizeof(cdn_kvp_t) * (session->cookies_count + 1));
				if (session->cookies == NULL) {
					ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for %l cookies KVP.", sizeof(cdn_kvp_t) * (session->cookies_count + 1), session->cookies_count + 1);
					return NGX_ERROR;
				}
				memcpy(cookies, session->cookies, sizeof(cdn_kvp_t) * session->cookies_count);
				session->cookies = cookies;
			}
			session->cookies_count ++;

			// Extract the cookie
			for (j=0, str2 = s2; ; j++, str2 = NULL) {
				subtoken = strtok_r(str2, cookie_subdelim, &saveptr2);
				if (subtoken == NULL)
					break;

				if (j == 0) {
					session->cookies[cookie_index].name = ngx_pcalloc(r->pool, strlen(subtoken) + 1);
					if (session->cookies[cookie_index].name == NULL) {
						ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for cookie name.", strlen(subtoken) + 1);
						return NGX_ERROR;
					}
					strcpy(session->cookies[cookie_index].name, subtoken);
				}
				else if (j == 1) {
					session->cookies[cookie_index].value = ngx_pcalloc(r->pool, strlen(subtoken) + 1);
					if (session->cookies[cookie_index].value == NULL) {
						ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for cookie value.", strlen(subtoken) + 1);
						return NGX_ERROR;
					}
					strcpy(session->cookies[cookie_index].value, subtoken);
				}
				else
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Malformed cookie %s", s0);
			}

			if (j == 2) {
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found cookie %s with value %s", session->cookies[cookie_index].name, session->cookies[cookie_index].value);
			}
		}
	}

	return NGX_OK;
}

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
ngx_int_t parse_dsn(session_t *session, ngx_http_request_t *r, db_dsn_t *dsn) {
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
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing MySQL DSN: %s", session->db_dsn);
	for (str = session->db_dsn, i = 0; ; str = NULL, i++) {
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

