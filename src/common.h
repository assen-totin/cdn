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
#include <mysql.h>
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
#define DEFAULT_unix_socket "/tmp/auth.socket"
#define DEFAULT_REQUEST_TYPE "json"
#define DEFAULT_TRANSPORT_TYPE "unix"
#define DEFAULT_JWT_COOKIE "none"
#define DEFAULT_JWT_HEADER "none"
#define DEFAULT_JWT_KEY "none"
#define DEFAULT_JWT_FIELD "none"
#define DEFAULT_JSON_EXTENDED "no"
#define DEFAULT_SQL_DSN "none"
#define DEFAULT_SQL_QUERY "none"

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
#define UNIX_BUFFER_CHUNK 1024
#define UNIX_SOCKET_TYPE SOCK_STREAM

#define REQUEST_TYPE_JSON "json"
#define REQUEST_TYPE_MYSQL "mysql"

#define TRANSPORT_TYPE_UNIX "unix" 
#define TRANSPORT_TYPE_MYSQL "mysql" 

// Structures
typedef struct {
	ngx_array_t loc_confs; 		// ngx_http_cdn_conf_t
} ngx_http_cdn_main_conf_t;

typedef struct {
	ngx_str_t fs_root;
	ngx_str_t fs_depth;
	ngx_str_t request_type;
	ngx_str_t transport_type;
	ngx_str_t unix_socket;
	ngx_str_t jwt_cookie;
	ngx_str_t jwt_header;
	ngx_str_t jwt_key;
	ngx_str_t jwt_field;
	ngx_str_t json_extended;
	ngx_str_t sql_dsn;
	ngx_str_t sql_query;
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
	char *json_extended;
	cdn_kvp_t *headers;
	int headers_count;
	cdn_kvp_t *cookies;
	int cookies_count;
	char *jwt_cookie;
	char *jwt_header;
	char *jwt_key;
	char *jwt_json;
	jwt_t *jwt;
	char *jwt_field;
	const char *jwt_value;
	char *sql_dsn;
	char *sql_query;
	char *hdr_if_none_match;
	time_t hdr_if_modified_since;
	char *unix_socket;
	char *unix_request;
	char *unix_response;
	MYSQL_RES *mysql_result;
} session_t;

typedef struct {
	char *host;
	char *port_str;
	int port;
	char *socket;
	char *user;
	char *password;
	char *db;
} sql_dsn_t;

