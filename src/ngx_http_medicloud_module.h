/**
 * Nginx media serving module for Medicloud.
 *
 * @author: Assen Totin assen.totin@curaden.ch
 */

#define __USE_XOPEN
#define _GNU_SOURCE

// Includes
#include <bson/bson.h>
#include <curl/curl.h>
#include <errno.h>
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

// Definitions
#define DEFAULT_ENABLE 1
#define DEFAULT_CONTENT_TYPE "application/octet-stream"
#define DEFAULT_ETAG "00000000000000000000000000000000"
#define DEFAULT_HTTP_CODE 500
#define HEADER_ETAG "ETag"
#define HEADER_AUTHORIZATION "Authorization"
#define HEADER_ACCEPT_RANGES "Accept-Ranges"
#define HEADER_CONTENT_DISPOSITION "Content-Disposition"
#define CONTENT_DISPOSITION_ATTACHMENT "attachment"
#define FS_DEFAULT_DEPTH "4"
#define FS_DEFAULT_ROOT "/usr/share/curaden/fs"
#define ERROR_MESSAGE_LENGTH 1024
#define AUTH_DEFAULT_SOCKET "/tmp/auth.socket"
#define AUTH_BUFFER_CHUNK 1024
#define AUTH_SOCKET_TYPE SOCK_STREAM

// Structures
typedef struct {
	ngx_array_t loc_confs; 		// ngx_http_medicloud_conf_t
} ngx_http_medicloud_main_conf_t;

typedef struct {
	ngx_str_t auth_socket;
	ngx_str_t fs_root;
	ngx_str_t fs_depth;
} ngx_http_medicloud_loc_conf_t;

typedef struct {
	char *etag;
	char *file;
	char *filename;
	char *content_type;
	char *content_disposition;
	char *error;
	u_char *data;
	time_t upload_date; 
	int32_t status;
	int64_t length;
} medicloud_file_t;

typedef struct {
	time_t exp;
	char *uri;
	uint fs_depth;
	char *fs_root;
	char *authorization;
	char *auth_socket;
	char *auth_req;
	char *auth_resp;
	char *hdr_authorisation;
	char *hdr_if_none_match;
	time_t hdr_if_modified_since;
} session_t;

// Prototypes
static void* ngx_http_medicloud_create_loc_conf(ngx_conf_t* directive);
static char* ngx_http_medicloud_merge_loc_conf(ngx_conf_t* directive, void* parent, void* child);
static char *ngx_http_medicloud_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_medicloud_handler(ngx_http_request_t* request);
static ngx_int_t get_metadata(session_t *session, ngx_http_request_t *r);
static ngx_int_t process_metadata(session_t *session, medicloud_file_t *meta_file, ngx_http_request_t *r);
static ngx_int_t read_fs(session_t *session, medicloud_file_t *dnld_file, ngx_http_request_t *r);
static ngx_int_t send_file(session_t *session, medicloud_file_t *dnld_file, ngx_http_request_t *r);
static void ngx_http_medicloud_cleanup(void *a);
char *from_ngx_str(ngx_pool_t *pool, ngx_str_t ngx_str);

// Globals: array to specify how to handle configuration directives.
static ngx_command_t ngx_http_medicloud_commands[] = {
	{
		ngx_string("medicloud"),
		NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
		ngx_http_medicloud_init,
		0,
		0,
		NULL
	},
	{
		ngx_string("fs_root"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_medicloud_loc_conf_t, fs_root),
		NULL
	},
	{
		ngx_string("fs_depth"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_medicloud_loc_conf_t, fs_depth),
		NULL
	},
	{
		ngx_string("auth_socket"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_medicloud_loc_conf_t, auth_socket),
		NULL
	},
	ngx_null_command
};

// Globals: module context
static ngx_http_module_t ngx_http_medicloud_module_ctx = {
	NULL,								// pre-configuration
	NULL,								// post-configuration
	NULL,								// allocations and initilizations of configurations for the main block configuration
	NULL,								// set the configuration based on the directives supplied in the configuration files
	NULL,								// allocations and initilizations of configurations for the server block configuration
	NULL,								// merge the server block configuration with the main block
	ngx_http_medicloud_create_loc_conf,	// allocations and initilizations of configurations for the location block configuration
	ngx_http_medicloud_merge_loc_conf	// callback to merge the location block configuration with the server block
};

// Globals: module definition
ngx_module_t ngx_http_medicloud_module = {
	NGX_MODULE_V1,
	&ngx_http_medicloud_module_ctx,	// pointer to be passed to calls made by NGINX’s API to your module
	ngx_http_medicloud_commands,	// pointer to a struct with extra configuration directives used by the module
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

