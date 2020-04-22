/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

// Prototypes
ngx_int_t ngx_http_cdn_module_init (ngx_cycle_t *cycle);
void ngx_http_cdn_module_end (ngx_cycle_t *cycle);
void *ngx_http_cdn_create_loc_conf(ngx_conf_t* directive);
char *ngx_http_cdn_merge_loc_conf(ngx_conf_t* directive, void* parent, void* child);
char *ngx_http_cdn_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

ngx_int_t ngx_http_cdn_handler(ngx_http_request_t* request);
ngx_int_t read_fs(session_t *session, cdn_file_t *dnld_file, ngx_http_request_t *r);
ngx_int_t send_file(session_t *session, cdn_file_t *dnld_file, ngx_http_request_t *r);
void ngx_http_cdn_cleanup(void *a);
char *from_ngx_str(ngx_pool_t *pool, ngx_str_t ngx_str);
ngx_int_t get_auth_token(session_t *session, ngx_http_request_t *r);
ngx_int_t get_path(session_t *session, cdn_file_t *metadata, ngx_http_request_t *r);
ngx_int_t get_stat(cdn_file_t *metadata, ngx_http_request_t *r);
ngx_int_t metadata_check(session_t *session, cdn_file_t *metadata, ngx_http_request_t *r);
void cleanup(cdn_file_t *metadata, ngx_http_request_t *r);

// Globals: array to specify how to handle configuration directives.
static ngx_command_t ngx_http_cdn_commands[] = {
	{
		ngx_string("cdn"),
		NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
		ngx_http_cdn_init,
		0,
		0,
		NULL
	},
	{
		ngx_string("cdn_fs_root"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_cdn_loc_conf_t, fs_root),
		NULL
	},
	{
		ngx_string("cdn_fs_depth"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_cdn_loc_conf_t, fs_depth),
		NULL
	},
	{
		ngx_string("cdn_request_type"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_cdn_loc_conf_t, request_type),
		NULL
	},
	{
		ngx_string("cdn_transport_type"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_cdn_loc_conf_t, transport_type),
		NULL
	},
	{
		ngx_string("cdn_unix_socket"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_cdn_loc_conf_t, unix_socket),
		NULL
	},
	{
		ngx_string("cdn_auth_cookie"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_cdn_loc_conf_t, auth_cookie),
		NULL
	},
	{
		ngx_string("cdn_auth_header"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_cdn_loc_conf_t, auth_header),
		NULL
	},
	{
		ngx_string("cdn_auth_method"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_cdn_loc_conf_t, auth_method),
		NULL
	},
	{
		ngx_string("cdn_jwt_key"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_cdn_loc_conf_t, jwt_key),
		NULL
	},
	{
		ngx_string("cdn_jwt_field"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_cdn_loc_conf_t, jwt_field),
		NULL
	},
	{
		ngx_string("cdn_all_cookies"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_cdn_loc_conf_t, all_cookies),
		NULL
	},
	{
		ngx_string("cdn_all_headers"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_cdn_loc_conf_t, all_headers),
		NULL
	},
	{
		ngx_string("cdn_sql_dsn"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_cdn_loc_conf_t, sql_dsn),
		NULL
	},
	{
		ngx_string("cdn_sql_query"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_cdn_loc_conf_t, sql_query),
		NULL
	},
	ngx_null_command
};

// Globals: module context
static ngx_http_module_t ngx_http_cdn_module_ctx = {
	NULL,							// pre-configuration
	NULL,							// post-configuration
	NULL,							// allocations and initilizations of configurations for the main block configuration
	NULL,							// set the configuration based on the directives supplied in the configuration files
	NULL,							// allocations and initilizations of configurations for the server block configuration
	NULL,							// merge the server block configuration with the main block
	ngx_http_cdn_create_loc_conf,	// allocations and initilizations of configurations for the location block configuration
	ngx_http_cdn_merge_loc_conf		// callback to merge the location block configuration with the server block
};

// Globals: module definition
ngx_module_t ngx_http_cdn_module = {
	NGX_MODULE_V1,
	&ngx_http_cdn_module_ctx,	// pointer to be passed to calls made by NGINX’s API to your module
	ngx_http_cdn_commands,		// pointer to a struct with extra configuration directives used by the module
	NGX_HTTP_MODULE,			// type of module defined
	NULL,						// hook into the initialisation of the master process (not implemented)
	ngx_http_cdn_module_init,	// hook into the module initialisation phase; happens prior to master process forking
	NULL,						// hook into the module initialisation in new process phase; happens as the worker processes are forked.
	NULL,						// hook into the initialisation of threads (not implemented)
	NULL,						// hook into the termination of a thread (not implemented)
	NULL,						// hook into the termination of a child process, such as a worker process
	ngx_http_cdn_module_end,	// hook into the termination of the master process
	NGX_MODULE_V1_PADDING
};

