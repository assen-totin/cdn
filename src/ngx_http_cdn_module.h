/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#define __USE_XOPEN
#define _GNU_SOURCE

// Includes
#include <curl/curl.h>
#include <errno.h>
#include <features.h>
#include <jwt.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// RHEL 7 or newer
#if __GLIBC_MINOR__ == 17
	#define RHEL7
#elif __GLIBC_MINOR__ == 28
	#define RHEL8
#endif

#ifdef RHEL7
	#include <bson.h>
#endif
#ifdef RHEL8
	#include <bson/bson.h>
#endif

// Definitions
#define DEFAULT_ENABLE 1
#define DEFAULT_CONTENT_TYPE "application/octet-stream"
#define DEFAULT_ETAG "00000000000000000000000000000000"
#define DEFAULT_ACCESS_CONTROL_ALLOW_ORIGIN "*"
#define DEFAULT_ACCESS_CONTROL_ALLOW_HEADERS "If-None-Match, If-Modified-Since"
#define DEFAULT_ACCESS_CONTROL_ALLOW_METHODS "GET, HEAD, OPTIONS"
#define DEFAULT_HTTP_CODE 500
#define DEFAULT_FS_DEPTH "4"
#define DEFAULT_FS_ROOT "/opt/cdn"
#define DEFAULT_AUTH_SOCKET "/tmp/auth.socket"
#define DEFAULT_REQUEST_TYPE "json"
#define DEFAULT_TRANSPORT_TYPE "unix"
#define DEFAULT_JWT_COOKIE "none"
#define DEFAULT_JWT_KEY "none"
#define DEFAULT_JWT_FIELD "none"

#define HEADER_ACCEPT_RANGES "Accept-Ranges"
#define HEADER_ACCESS_CONTROL_ALLOW_ORIGIN "Access-Control-Allow-Origin"
#define HEADER_ACCESS_CONTROL_ALLOW_HEADERS "Access-Control-Allow-Headers"
#define HEADER_ACCESS_CONTROL_ALLOW_METHODS "Access-Control-Allow-Methods"
#define HEADER_AUTHORIZATION "Authorization"
#define HEADER_CONTENT_DISPOSITION "Content-Disposition"
#define HEADER_ETAG "ETag"
#define HEADER_IF_MODIFIED_SINCE "If-Modified-Since"
#define HEADER_IF_NONE_MATCH "If-None-Match"

#define CONTENT_DISPOSITION_ATTACHMENT "attachment"
#define ERROR_MESSAGE_LENGTH 1024
#define AUTH_BUFFER_CHUNK 1024
#define AUTH_SOCKET_TYPE SOCK_STREAM
#define REQUEST_TYPE_JSON "json"
#define TRANSPORT_TYPE_UNIX "unix" 

// Structures
typedef struct {
	ngx_array_t loc_confs; 		// ngx_http_cdn_conf_t
} ngx_http_cdn_main_conf_t;

typedef struct {
	ngx_str_t fs_root;
	ngx_str_t fs_depth;
	ngx_str_t request_type;
	ngx_str_t transport_type;
	ngx_str_t auth_socket;
	ngx_str_t jwt_cookie;
	ngx_str_t jwt_key;
	ngx_str_t jwt_field;
} ngx_http_cdn_loc_conf_t;

typedef struct {
	char *file;
	char *filename;
	char *path;
	char *content_type;
	char *content_disposition;
	char *etag;
	char *error;
	u_char *data;
	time_t upload_date; 
	int32_t status;
	int64_t length;
} cdn_file_t;

typedef struct {
	char *name;
	char *value;
} cdn_kvp_t;

typedef struct {
	time_t exp;
	char *uri;
	uint fs_depth;
	char *fs_root;
	char *request_type;
	char *transport_type;
	cdn_kvp_t *headers;
	int headers_count;
	cdn_kvp_t *cookies;
	int cookies_count;
	char *jwt_cookie;
	char *jwt_key;
	char *jwt_json;
	jwt_t *jwt;
	char *jwt_field;
	const char *jwt_value;
	char *auth_req;
	char *auth_resp;

	char *auth_socket;

	char *hdr_if_none_match;
	time_t hdr_if_modified_since;
} session_t;

// Prototypes
static void* ngx_http_cdn_create_loc_conf(ngx_conf_t* directive);
static char* ngx_http_cdn_merge_loc_conf(ngx_conf_t* directive, void* parent, void* child);
static char *ngx_http_cdn_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_cdn_handler(ngx_http_request_t* request);
static ngx_int_t read_fs(session_t *session, cdn_file_t *dnld_file, ngx_http_request_t *r);
static ngx_int_t send_file(session_t *session, cdn_file_t *dnld_file, ngx_http_request_t *r);
static void ngx_http_cdn_cleanup(void *a);
static char *from_ngx_str(ngx_pool_t *pool, ngx_str_t ngx_str);
static ngx_int_t get_header(session_t *session, ngx_http_request_t *r, char *name, ngx_str_t ngx_str);
static ngx_int_t get_cookies(session_t *session, ngx_http_request_t *r);
static ngx_int_t get_jwt(session_t *session, ngx_http_request_t *r);
static ngx_int_t get_path(session_t *session, cdn_file_t *metadata, ngx_http_request_t *r);
static ngx_int_t get_stat(cdn_file_t *metadata, ngx_http_request_t *r);
static ngx_int_t request_json(session_t *session, ngx_http_request_t *r);
static ngx_int_t response_json(session_t *session, cdn_file_t *meta_file, ngx_http_request_t *r);
static ngx_int_t metadata_unix(session_t *session, ngx_http_request_t *r);
static ngx_int_t metadata_check(session_t *session, cdn_file_t *metadata, ngx_http_request_t *r);
static void cleanup(cdn_file_t *metadata, ngx_http_request_t *r);

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
		ngx_string("cdn_auth_socket"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_cdn_loc_conf_t, auth_socket),
		NULL
	},
	{
		ngx_string("cdn_jwt_cookie"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_cdn_loc_conf_t, jwt_cookie),
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
	ngx_null_command
};

// Globals: module context
static ngx_http_module_t ngx_http_cdn_module_ctx = {
	NULL,								// pre-configuration
	NULL,								// post-configuration
	NULL,								// allocations and initilizations of configurations for the main block configuration
	NULL,								// set the configuration based on the directives supplied in the configuration files
	NULL,								// allocations and initilizations of configurations for the server block configuration
	NULL,								// merge the server block configuration with the main block
	ngx_http_cdn_create_loc_conf,	// allocations and initilizations of configurations for the location block configuration
	ngx_http_cdn_merge_loc_conf	// callback to merge the location block configuration with the server block
};

// Globals: module definition
ngx_module_t ngx_http_cdn_module = {
	NGX_MODULE_V1,
	&ngx_http_cdn_module_ctx,	// pointer to be passed to calls made by NGINX’s API to your module
	ngx_http_cdn_commands,	// pointer to a struct with extra configuration directives used by the module
	NGX_HTTP_MODULE,				// type of module defined
	NULL,							// hook into the initialisation of the master process
	NULL,							// hook into the module initialisation phase; happens prior to master process forking
	NULL,							// hook into the module initialisation in new process phase; happens as the worker processes are forked.
	NULL,							// hook into the initialisation of threads
	NULL,							// hook into the termination of a thread
	NULL,							// hook into the termination of a child process (such as a worker process)
	NULL,							// hook into the termination of the master process
	NGX_MODULE_V1_PADDING
};
