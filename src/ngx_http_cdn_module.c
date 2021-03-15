/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "ngx_http_cdn_module.h"
#include "cache.h"
#include "index.h"
#include "fs.h"
#include "http.h"
#include "utils.h"
#include "murmur3_32.h"

/**
 * Module initialisation
 */
ngx_int_t ngx_http_cdn_module_init (ngx_cycle_t *cycle) {
	int ret; 

#ifdef CDN_ENABLE_MONGO
	// Init Mongo
	mongoc_init();
#endif

#ifdef CDN_ENABLE_MYSQL
	// Init MySQL
	if ((ret = mysql_library_init(0, NULL, NULL)) > 0) {
		ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Failed to init MySQL library: error %l.", ret);
		return NGX_ERROR;
	}
#endif

#ifdef CDN_ENABLE_ORACLE
	// Init Oracle
	if (! OCI_Initialize(NULL, NULL, OCI_ENV_DEFAULT | OCI_ENV_CONTEXT | OCI_ENV_THREADED)) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "Failed to init Oracle OCI library: %s", OCI_ErrorGetString(OCI_GetLastError()));
		return NGX_ERROR;
	}
#endif

	// Check libxml version
	LIBXML_TEST_VERSION;

	// Init cURL
	curl_global_init(CURL_GLOBAL_DEFAULT);

	// Init the globals
	if ((globals = malloc(sizeof(globals_t))) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Failed to allocate %l bytes for globals.", sizeof(globals_t));
		return NGX_ERROR;
	}
	globals->instances = NULL;
	globals->instances_cnt = 0;

	return NGX_OK;
}

/**
 * Module termination
 */
void ngx_http_cdn_module_end(ngx_cycle_t *cycle) {
	int i;
	instance_t *instance;

#ifdef CDN_ENABLE_MYSQL
	mysql_library_end();
#endif
#ifdef CDN_ENABLE_ORACLE
	OCI_Cleanup();
#endif

	// Clean all instances
	for (i=0; i < globals->instances_cnt; i++) {
		instance = &globals->instances[i];

		cache_destroy(instance->cache);

		index_destroy(instance->index);

		fs_destroy(instance->fs);

		if (instance->jwt_key)
			free(instance->jwt_key);

		if (instance->dsn) {
			if (instance->dsn->dsn)
				free(instance->dsn->dsn);
			if (instance->dsn->host)
				free(instance->dsn->host);
			if (instance->dsn->port_str)
				free(instance->dsn->port_str);
			if (instance->dsn->user)
				free(instance->dsn->user);
			if (instance->dsn->password)
				free(instance->dsn->password);
			if (instance->dsn->db)
				free(instance->dsn->db);
			free(instance->dsn);
		}

		if (instance->matrix_dnld)
			free(instance->matrix_dnld);

		if (instance->matrix_upld)
			free(instance->matrix_upld);

		if (instance->matrix_del)
			free(instance->matrix_del);
	}

	free(globals);
}

/**
 * Create location configuration
 */
void* ngx_http_cdn_create_loc_conf(ngx_conf_t* cf) {
	ngx_http_cdn_loc_conf_t *loc_conf;

	if ((loc_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cdn_loc_conf_t))) == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Failed to allocate %l bytes for location config.", sizeof(ngx_http_cdn_loc_conf_t));
		return NGX_CONF_ERROR;
	}

	return loc_conf;
}

/**
 * Merge location configuration
 */
char* ngx_http_cdn_merge_loc_conf(ngx_conf_t* cf, void* void_parent, void* void_child) {
	ngx_http_cdn_loc_conf_t *parent = void_parent;
	ngx_http_cdn_loc_conf_t *child = void_child;

	ngx_conf_merge_str_value(child->server_id, parent->server_id, DEFAULT_SERVER_ID);
	ngx_conf_merge_str_value(child->fs_root, parent->fs_root, DEFAULT_FS_ROOT);
	ngx_conf_merge_str_value(child->fs_depth, parent->fs_depth, DEFAULT_FS_DEPTH);
	ngx_conf_merge_str_value(child->index_prefix, parent->index_prefix, DEFAULT_INDEX_PREFIX);
	ngx_conf_merge_str_value(child->request_type, parent->request_type, DEFAULT_REQUEST_TYPE);
	ngx_conf_merge_str_value(child->transport_type, parent->transport_type, DEFAULT_TRANSPORT_TYPE);
	ngx_conf_merge_str_value(child->unix_socket, parent->unix_socket, DEFAULT_UNIX_SOCKET);
	ngx_conf_merge_str_value(child->tcp_host, parent->tcp_host, DEFAULT_TCP_HOST);
	ngx_conf_merge_str_value(child->tcp_port, parent->tcp_port, DEFAULT_TCP_PORT);
	ngx_conf_merge_str_value(child->auth_cookie, parent->auth_cookie, DEFAULT_AUTH_COOKIE);
	ngx_conf_merge_str_value(child->auth_header, parent->auth_header, DEFAULT_AUTH_HEADER);
	ngx_conf_merge_str_value(child->auth_type, parent->auth_type, DEFAULT_AUTH_METOD);
	ngx_conf_merge_str_value(child->auth_filter, parent->auth_filter, DEFAULT_AUTH_FILTER);
	ngx_conf_merge_str_value(child->jwt_key, parent->jwt_key, DEFAULT_JWT_KEY);
	ngx_conf_merge_str_value(child->jwt_field, parent->jwt_field, DEFAULT_JWT_FIELD);
	ngx_conf_merge_str_value(child->all_headers, parent->all_headers, DEFAULT_ALL_HEADERS);
	ngx_conf_merge_str_value(child->all_cookies, parent->all_cookies, DEFAULT_ALL_COOKIES);
	ngx_conf_merge_str_value(child->db_dsn, parent->db_dsn, DEFAULT_DB_DSN);
	ngx_conf_merge_str_value(child->sql_delete, parent->sql_delete, DEFAULT_SQL_QUERY_DELETE);
	ngx_conf_merge_str_value(child->sql_insert, parent->sql_insert, DEFAULT_SQL_QUERY_INSERT);
	ngx_conf_merge_str_value(child->sql_select, parent->sql_select, DEFAULT_SQL_QUERY_SELECT);
	ngx_conf_merge_str_value(child->http_url, parent->http_url, DEFAULT_HTTP_URL);
	ngx_conf_merge_str_value(child->mongo_db, parent->mongo_db, DEFAULT_MONGO_DB);
	ngx_conf_merge_str_value(child->mongo_collection, parent->mongo_collection, DEFAULT_MONGO_COLLECTION);
	ngx_conf_merge_str_value(child->mongo_filter, parent->mongo_filter, DEFAULT_MONGO_FILTER);
	ngx_conf_merge_str_value(child->cors_origin, parent->cors_origin, DEFAULT_ACCESS_CONTROL_ALLOW_ORIGIN);
	ngx_conf_merge_str_value(child->read_only, parent->read_only, DEFAULT_READ_ONLY);
	ngx_conf_merge_str_value(child->cache_size, parent->cache_size, DEFAULT_CACHE_SIZE);
	ngx_conf_merge_str_value(child->matrix_upld, parent->matrix_upld, DEFAULT_MATRIX_UPLD);
	ngx_conf_merge_str_value(child->matrix_dnld, parent->matrix_dnld, DEFAULT_MATRIX_DNLD);
	ngx_conf_merge_str_value(child->matrix_del, parent->matrix_del, DEFAULT_MATRIX_DEL);

	// Calculate and save instance ID hash only if working on real location
	if (child->fs_root.len != strlen(DEFAULT_FS_ROOT)) {
		murmur3_32((void *)child->fs_root.data, child->fs_root.len, 42, (void *) &child->instance_id);
		ngx_log_error(NGX_LOG_INFO, cf->log, 0, "Setting instance ID to %uD", child->instance_id);
	}

	return NGX_CONF_OK;
}

/**
 * Init module and set handler
 */
char *ngx_http_cdn_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_core_loc_conf_t  *clcf;

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_cdn_handler;

	return NGX_CONF_OK;
}

/**
 * Content handler
 */
ngx_int_t ngx_http_cdn_handler(ngx_http_request_t *r) {
	ngx_int_t ret;

	// OPTIONS handling (CORS)
	if (r->method & (NGX_HTTP_OPTIONS))
		return cdn_handler_options(r);

	// POST set callback and return
	if (r->method & (NGX_HTTP_POST | NGX_HTTP_PUT)) {
		// Set body handler
		if ((ret = ngx_http_read_client_request_body(r, cdn_handler_post)) >= NGX_HTTP_SPECIAL_RESPONSE)
			return ret;

		return NGX_DONE;
	}

	// GET, HEAD and DELETE
	if (r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD | NGX_HTTP_DELETE))
		return cdn_handler_get(r);

	ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "HTTP method not supported: %l", r->method);
	return NGX_ERROR;
} 

