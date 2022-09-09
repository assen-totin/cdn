/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

//// PRE-INCLUDES

#define __USE_XOPEN
#define _GNU_SOURCE

//// INCLUDES

#include "modules.h"
#include <curl/curl.h>
#include <errno.h>
#include <features.h>
#include <libxml/xmlwriter.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifdef CDN_ENABLE_JWT
#include <jwt.h>
#endif

#ifdef CDN_ENABLE_MONGO
#include <mongoc.h>
#endif

#ifdef CDN_ENABLE_MYSQL
#include <mysql.h>
#endif

#ifdef CDN_ENABLE_ORACLE
#include <ocilib.h>
#endif

#ifdef CDN_ENABLE_POSTGRESQL
#include <libpq-fe.h>
#endif

#ifdef CDN_ENABLE_REDIS
#include <hiredis/hiredis.h>
#endif

// RHEL 7 or newer
#if __GLIBC_MINOR__ == 17
	#define RHEL7
#elif __GLIBC_MINOR__ == 28
	#define RHEL8
#elif __GLIBC_MINOR__ == 34
	#define RHEL9
#endif

#ifdef RHEL7
	#include <bson.h>
#endif
#ifdef RHEL8
	#include <bson/bson.h>
#endif
#ifdef RHEL9
	#include <bson/bson.h>
#endif

//// DEFINITIONS

#define DEFAULT_ACCESS_CONTROL_ALLOW_ORIGIN "*"
#define DEFAULT_ACCESS_CONTROL_ALLOW_HEADERS "If-None-Match, If-Modified-Since, If-Range, Range, Authorization"
#define DEFAULT_ACCESS_CONTROL_ALLOW_METHODS "GET, HEAD, POST, PUT, OPTIONS, DELETE"
#define DEFAULT_ALL_COOKIES "no"
#define DEFAULT_ALL_HEADERS "no"
#define DEFAULT_AUTH_HEADER "none"
#define DEFAULT_AUTH_COOKIE "none"
#define DEFAULT_AUTH_FILTER "none"
#define DEFAULT_AUTH_METOD "none"
#define DEFAULT_CACHE_SIZE "0"
#define DEFAULT_CONTENT_TYPE "application/octet-stream"
#define DEFAULT_CONTENT_DISPOSITION "none"
#define DEFAULT_DB_DSN "none"
#define DEFAULT_ETAG "00000000000000000000000000000000"
#define DEFAULT_FILE_NAME "unnamed"
#define DEFAULT_FS_DEPTH "4"
#define DEFAULT_FS_ROOT "/opt/cdn"
#define DEFAULT_HTTP_URL "http://example.com"
#define DEFAULT_INDEX_PREFIX "______"
#define DEFAULT_JWT_KEY "none"
#define DEFAULT_JWT_FIELD "none"
#define DEFAULT_MATRIX_ALLOW "allow"
#define DEFAULT_MATRIX_DENY "deny"
#define DEFAULT_MATRIX_DEL "allow:deny:deny:deny"
#define DEFAULT_MATRIX_DNLD "allow:deny:deny:deny"
#define DEFAULT_MATRIX_UPLD "allow:allow:deny:deny"
#define DEFAULT_MONGO_COLLECTION "cdn"
#define DEFAULT_MONGO_DB "cdn"
#define DEFAULT_MONGO_FILTER "{'file_id': '%s', 'auth_value': '%s'}"
#define DEFAULT_READ_ONLY "no"
#define DEFAULT_REQUEST_TYPE "none"
#define DEFAULT_SERVER_ID "1"
#define DEFAULT_SQL_QUERY_DELETE "DELETE FROM cdn WHERE file_id='%s'"
#define DEFAULT_SQL_QUERY_INSERT "REPLACE INTO cdn (auth_value, file_id, filename, content_type, content_disposition, etag) VALUES ('%s','%s','%s',%u,'%s','%s', %u,'%s')"
#define DEFAULT_SQL_QUERY_SELECT "SELECT * FROM cdn WHERE file_id='%s' AND auth_value='%s'"
#define DEFAULT_TCP_HOST "example.com"
#define DEFAULT_TCP_PORT "12345"
#define DEFAULT_TRANSPORT_TYPE "none"
#define DEFAULT_UNIX_SOCKET "/tmp/auth.socket"
#define DEFAULT_VHOST_ID "00000000"

#define CACHE_BTREE_DEPTH 128
#define CACHE_KEY_LEN 16
#define CACHE_SIZE_MULTIPLIER 1048576

#define EAGAIN_MAX_COUNT 10
#define EAGAIN_SLEEP 5

#define HASH_SIZE 32

#define HEADER_ACCEPT_RANGES "Accept-Ranges"
#define HEADER_ACCESS_CONTROL_ALLOW_ORIGIN "Access-Control-Allow-Origin"
#define HEADER_ACCESS_CONTROL_ALLOW_HEADERS "Access-Control-Allow-Headers"
#define HEADER_ACCESS_CONTROL_ALLOW_METHODS "Access-Control-Allow-Methods"
#define HEADER_AUTHORIZATION "Authorization"
#define HEADER_CONTENT_DISPOSITION "Content-Disposition"
#define HEADER_CONTENT_RANGE "Content-Range"
#define HEADER_ETAG "ETag"

#define CONTENT_DISPOSITION_ATTACHMENT "attachment"
#define ERROR_MESSAGE_LENGTH 1024

#define MAX_EXT_SIZE 16
#define MAX_SERVER_ID 48
#define MAX_VER 9999

#define MATRIX_ALLOW_STATUS 200
#define MATRIX_DENY_STATUS 403

#define AUTH_TYPE_JWT "jwt"
#define AUTH_TYPE_SESSION "session"

#define CONTENT_TYPE_MPFD "multipart/form-data"
#define CONTENT_TYPE_AXWFU "application/x-www-form-urlencoded"
#define CONTENT_TYPE_TEXT_PLAIN "text/plain"

#define REQUEST_TYPE_JSON "json"
#define REQUEST_TYPE_MONGO "mongo"
#define REQUEST_TYPE_MYSQL "mysql"
#define REQUEST_TYPE_ORACLE "oracle"
#define REQUEST_TYPE_POSTGRESQL "postgresql"
#define REQUEST_TYPE_XML "xml"

#define SOCKET_BUFFER_CHUNK 1500
#define SOCKET_TYPE_TCP 1
#define SOCKET_TYPE_UNUX 2

#define TRANSPORT_TYPE_HTTP "http"
#define TRANSPORT_TYPE_INTERNAL "internal"
#define TRANSPORT_TYPE_MONGO "mongo"
#define TRANSPORT_TYPE_MYSQL "mysql"
#define TRANSPORT_TYPE_ORACLE "oracle"
#define TRANSPORT_TYPE_POSTGRESQL "postgresql"
#define TRANSPORT_TYPE_REDIS "redis"
#define TRANSPORT_TYPE_TCP "tcp"
#define TRANSPORT_TYPE_UNIX "unix"

// STRUCTURES

// Main config
typedef struct {
	ngx_array_t loc_confs; 		// ngx_http_cdn_conf_t
} ngx_http_cdn_main_conf_t;

// Local config
typedef struct {
	ngx_str_t server_id;
	ngx_str_t vhost_id;
	uint32_t instance_id;
	ngx_str_t fs_root;
	ngx_str_t fs_depth;
	ngx_str_t index_prefix;
	ngx_str_t request_type;
	ngx_str_t transport_type;
	ngx_str_t unix_socket;
	ngx_str_t tcp_host;
	ngx_str_t tcp_port;
	ngx_str_t auth_cookie;
	ngx_str_t auth_header;
	ngx_str_t auth_type;
	ngx_str_t auth_filter;
	ngx_str_t jwt_key;
	ngx_str_t jwt_field;
	ngx_str_t all_cookies;
	ngx_str_t all_headers;
	ngx_str_t db_dsn;
	ngx_str_t sql_select;
	ngx_str_t sql_insert;
	ngx_str_t sql_delete;
	ngx_str_t http_url;
	ngx_str_t mongo_db;
	ngx_str_t mongo_collection;
	ngx_str_t mongo_filter;
	ngx_str_t cors_origin;
	ngx_str_t read_only;
	ngx_str_t cache_size;
	ngx_str_t matrix_del;
	ngx_str_t matrix_dnld;
	ngx_str_t matrix_upld;
} ngx_http_cdn_loc_conf_t;

// Metadata
typedef struct {
	char *hash;
	char *ext;
	char *ext16;
	char *pack;
	char *file;
	char *file16;
	char *filename;
	char *path;
	char *content_type;
	char *content_disposition;
	char *etag;
	char *error;
	char *auth_value;
	u_char *data;
	time_t upload_timestamp; 
	int64_t length;
	int32_t status;
	int32_t ver;
} metadata_t;

// Key-value pair
typedef struct {
	char *name;
	char *value;
} cdn_kvp_t;

// Database DSN
typedef struct {
	char *dsn;
	char *host;
	char *port_str;
	int port;
	char *socket;
	char *user;
	char *password;
	char *db;
} dsn_t;

// Authentication matrix
typedef struct {
	uint auth_resp;
	uint auth_noresp;
	uint noauth_resp;
	uint noauth_noresp;
} auth_matrix_t;

// FS structure
typedef struct {
	int server_id;
	int depth;
	char *root;
} fs_t;

// BTree node structure
typedef struct btree_s btree_t;
struct btree_s {
	btree_t *left;
	btree_t *right;
};

// Cache structure
typedef struct {
	btree_t* root;
	void *list;
	uint64_t list_cnt;
	uint64_t mem_used;
	uint64_t mem_max;
	uint64_t *btree_mask;
} cache_t;

// Cache payload element structure
typedef struct {
	char *ext;
	char *data;
} cache_payload_el_t ;

// Cache payload structure
typedef struct {
	int count;
	cache_payload_el_t *elements;
} cache_payload_t;

// Index structure
typedef struct {
	int fd;
	char *prefix;
	int year;
	int month;
	int day;
	int hour;
} index_t;

// Range header
typedef struct {
	int64_t start;		// -1 means read "end" bytes from the end
	int64_t end;		// -1 means read from "start" to end of file
} hdr_range_t;

// Globals for a CDN instance
typedef struct {
	uint32_t id;
	char *jwt_key;
	dsn_t *dsn;
	auth_matrix_t *matrix_dnld;
	auth_matrix_t *matrix_del;
	auth_matrix_t *matrix_upld;
	cache_t *cache;
	index_t *index;
	fs_t *fs;
	int tm_gmtoff;
} instance_t;

// Session
typedef struct {
	instance_t *instance;
	ngx_http_request_t *r;
	time_t exp;
	char *read_only;
	char *http_method;
	char *request_type;
	char *cors_origin;
	char *transport_type;
	char *all_cookies;
	char *all_headers;
	cdn_kvp_t *headers;
	int headers_count;
	cdn_kvp_t *cookies;
	int cookies_count;
	char *auth_cookie;
	char *auth_header;
	char *auth_type;
	char *auth_token;
	char *auth_value;
	char *auth_filter;
	char *auth_request;
	char *auth_response;
	int auth_response_len;
	int auth_response_pos;
	int auth_response_count;
	char *jwt_json;
	char *jwt_field;
	char *sql_query;
	char *sql_query2;
	char *db_dsn;
	char *hdr_if_none_match;
	time_t hdr_if_modified_since;
	time_t hdr_if_range_time;
	char *hdr_if_range_etag;
	char *hdr_range;
	hdr_range_t *hdr_ranges;
	int hdr_ranges_cnt;
	char *unix_socket;
	char *tcp_host;
	int tcp_port;
	char *http_url;
	CURL *curl;
#ifdef CDN_ENABLE_JWT
	jwt_t *jwt;
#endif
#ifdef CDN_ENABLE_MONGO
	char *mongo_db;
	char *mongo_collection;
	char *mongo_filter;
#endif
#ifdef CDN_ENABLE_MYSQL
	MYSQL_RES *mysql_result;
#endif
#ifdef CDN_ENABLE_ORACLE
    OCI_Connection *oracle_connection;
    OCI_Statement *oracle_statement;
	OCI_Resultset *oracle_result;
#endif
#ifdef CDN_ENABLE_POSTGRESQL
	PGconn *postgresql_connection;
	PGresult *postgresql_result;
#endif
} session_t;

// Upload
typedef struct {
	char *rb;
	bool rb_malloc;
	CURL *curl;
} upload_t;

// Globals
typedef struct {
	instance_t *instances;
	int instances_cnt;
	pthread_mutex_t lock_instance;
	pthread_mutex_t lock_index;
	pthread_mutex_t lock_cache;
} globals_t;

//// ENUMERATORS

enum {
	METADATA_NONE = 0,
	METADATA_SELECT,
	METADATA_INSERT,
	METADATA_UPDATE,
	METADATA_DELETE
};

enum {
	UPLOAD_CONTENT_TYPE_NONE = 0,
	UPLOAD_CONTENT_TYPE_MPFD,
	UPLOAD_CONTENT_TYPE_AXWFU,
};

enum {
	INDEX_ACTION_NONE = 0,
	INDEX_ACTION_INSERT,
	INDEX_ACTION_UPDATE,
	INDEX_ACTION_DELETE,
};

//// GLOBALS
//extern globals_t *globals;

