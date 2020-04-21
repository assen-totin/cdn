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

	f = ngx_pcalloc(r->pool, strlen(value) + 1);
	if (f == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata %s.", field_name, strlen(value) + 1);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	strcpy(f, value);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata %s: %s", field_name, f);

	*field = f;

	return NGX_OK;
}


