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

