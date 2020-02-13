/**
 * Nginx media serving module for Medicloud.
 *
 * @author: Assen Totin assen.totin@curaden.ch
 */

// Includes
#include <curl/curl.h>
#include <errno.h>
#include <jwt.h>
#include <mongoc.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

// Definitions
#define DEFAULT_CONTENT_TYPE "application/octet-stream"
#define DEFAULT_ETAG "00000000000000000000000000000000"
#define DEFAULT_FILENAME "unknown.dat"
#define LOCATION_PUBLIC1 "public"
#define LOCATION_PUBLIC2 "profile"
#define LOCATION_PRIVATE "private"
#define DNLD_ATTACHMENT "download"
#define DNLD_STREAM "stream"
#define HEADER_ETAG "ETag"
#define HEADER_CONTENT_DISPOSITION "Content-Disposition"
#define HEADER_AUTHORIZATION "Authorization"
#define HEADER_ACCEPT_RANGES "Accept-Ranges"
#define MONGO_DEFAULT_URL "mongodb://localhost:27017"
#define MONGO_DEFAULT_DB "practicedent"
#define MONGO_DEFAULT_ENABLED 1
#define MONGO_COLLECTION_FILES "fs.files"
#define GRIDFS_COLLECTION_FILES "fs"
#define FS_DEFAULT_ENABLED 1
#define FS_DEFAULT_DEPTH 4
#define FS_DEFAULT_ROOT "/usr/share/curaden/fs"
#define FS_METADATA_COLLECTION "fsmd"
#define WEB_TOKEN "medicloud_token"
#define ERROR_MESSAGE_LENGTH 1024

// Structures
typedef struct {
	ngx_array_t loc_confs; 		// ngx_http_medicloud_conf_t
} ngx_http_medicloud_main_conf_t;

typedef struct {
	ngx_str_t jwt_key;
	ngx_flag_t mongo_enabled;
	ngx_str_t mongo_url;
	ngx_str_t mongo_db;
	ngx_flag_t fs_enabled;
	uint fs_depth;
	ngx_str_t fs_root;
} ngx_http_medicloud_loc_conf_t;

typedef struct {
	mongoc_client_t *conn;
	mongoc_collection_t *collection;
	mongoc_cursor_t *cursor;
	mongoc_gridfs_t *gridfs;
	mongoc_gridfs_file_t *file;
	mongoc_stream_t *stream;
	bson_t filter;
	jwt_t *jwt;
} medicloud_mongo_t;

typedef struct {
	const char *etag;
	const char *md5;
	const char *filename;
	const char *content_type;
	char uid[25];
	char tid[25];
	int64_t length;
	time_t upload_date; 
	int32_t access; 
} medicloud_mongo_file_t;

typedef struct {
	int64_t length; 
	time_t upload_date; 
	char *content_type;
	char *etag;
	char *filename;
	u_char *data;
} medicloud_grid_file_t;

typedef struct {
	char *id;					// Media ID
	const char *jwt_key;
	const char *uid;
	const char *tid;
	time_t exp;
	char *if_none_match;
	char *uri;
	char *uri_dup;
	char *bucket;
	char *attachment;
	bool is_attachment;
	bool mongo_enabled;
	char *mongo_url;
	char *mongo_db;
	bool fs_enabled;
	uint fs_depth;
	char *fs_root;
	char *authorization;
	char *token;
} sm_t;

// Prototypes
static ngx_int_t ngx_http_medicloud_module_start(ngx_cycle_t *cycle); 
static void ngx_http_medicloud_master_end(ngx_cycle_t *cycle);
static void* ngx_http_medicloud_create_loc_conf(ngx_conf_t* directive);
static char* ngx_http_medicloud_merge_loc_conf(ngx_conf_t* directive, void* parent, void* child);
static char *ngx_http_medicloud_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_medicloud_handler(ngx_http_request_t* request);
static ngx_int_t get_metadata(medicloud_mongo_t *mongo, medicloud_mongo_file_t *mongo_file, sm_t *sm, ngx_http_request_t *r, char *collection_name);
static ngx_int_t init_grid_file(medicloud_mongo_file_t *mongo_file, sm_t *sm, medicloud_grid_file_t *grid_file, ngx_http_request_t *r);
static ngx_int_t read_gridfs(medicloud_mongo_t *mongo, sm_t *sm, medicloud_grid_file_t *grid_file, ngx_http_request_t *r);
static ngx_int_t read_fs(medicloud_mongo_t *mongo, sm_t *sm, medicloud_grid_file_t *grid_file, ngx_http_request_t *r);
static ngx_int_t send_file(sm_t *sm, medicloud_grid_file_t *grid_file, ngx_http_request_t *r);
void cleanup_mongo(medicloud_mongo_t *mongo);
char *from_ngx_str(ngx_pool_t *pool, ngx_str_t ngx_str);

// Globals: array to specify how to handle configuration directives.
static ngx_command_t ngx_http_medicloud_commands[] = {
	{
		ngx_string("medicloud"),
		NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
		ngx_http_medicloud_init,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_medicloud_loc_conf_t, mongo_url),
		NULL
	},
	{
		ngx_string("mongo_url"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_medicloud_loc_conf_t, mongo_url),
		NULL
	},
	{
		ngx_string("jwt_key"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_medicloud_loc_conf_t, jwt_key),
		NULL
	},
	{
		ngx_string("mongo_db"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_medicloud_loc_conf_t, mongo_db),
		NULL
	},
	ngx_null_command
};

// Globals: module context
static ngx_http_module_t ngx_http_medicloud_module_ctx = {
	NULL,								// pre-configuration
	NULL,								// pre-configuration
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
	NULL,			// hook into the initialisation of the master process
	ngx_http_medicloud_module_start,							// hook into the module initialisation phase; happens prior to master process forking
	NULL,							// hook into the module initialisation in new process phase; happens as the worker processes are forked.
	NULL,							// hook into the initialisation of threads
	NULL,							// hook into the termination of a thread
	NULL,							// hook into the termination of a child process (such as a worker process)
	ngx_http_medicloud_master_end,				// hook into the termination of the master process
	NGX_MODULE_V1_PADDING
};

