/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#define __USE_XOPEN
#define _GNU_SOURCE

// Includes
#include "modules.h"
#include <curl/curl.h>
#include <errno.h>
#include <features.h>
#include <libxml/xmlwriter.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
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
#define DEFAULT_CONTENT_TYPE "application/octet-stream"
#define DEFAULT_ETAG "00000000000000000000000000000000"
#define DEFAULT_ACCESS_CONTROL_ALLOW_ORIGIN "*"
#define DEFAULT_ACCESS_CONTROL_ALLOW_HEADERS "If-None-Match, If-Modified-Since"
#define DEFAULT_ACCESS_CONTROL_ALLOW_METHODS "GET, HEAD, POST, OPTIONS, DELETE"
#define DEFAULT_HTTP_CODE 500
#define DEFAULT_SERVER_ID 1
#define DEFAULT_FS_DEPTH "4"
#define DEFAULT_FS_ROOT "/opt/cdn"
#define DEFAULT_TCP_HOST "example.com"
#define DEFAULT_TCP_PORT "12345"
#define DEFAULT_UNIX_SOCKET "/tmp/auth.socket"
#define DEFAULT_HTTP_URL "http://example.com"
#define DEFAULT_REQUEST_TYPE "none"
#define DEFAULT_TRANSPORT_TYPE "none"
#define DEFAULT_AUTH_HEADER "none"
#define DEFAULT_AUTH_COOKIE "none"
#define DEFAULT_AUTH_METOD "none"
#define DEFAULT_JWT_KEY "none"
#define DEFAULT_JWT_FIELD "none"
#define DEFAULT_ALL_COOKIES "no"
#define DEFAULT_ALL_HEADERS "no"
#define DEFAULT_DB_DSN "none"
#define DEFAULT_SQL_QUERY "none"
#define DEFAULT_MONGO_DB "none"
#define DEFAULT_MONGO_COLLECTION "none"

#define MAX_SERVER_ID 48

#define HEADER_ACCEPT_RANGES "Accept-Ranges"
#define HEADER_ACCESS_CONTROL_ALLOW_ORIGIN "Access-Control-Allow-Origin"
#define HEADER_ACCESS_CONTROL_ALLOW_HEADERS "Access-Control-Allow-Headers"
#define HEADER_ACCESS_CONTROL_ALLOW_METHODS "Access-Control-Allow-Methods"
#define HEADER_AUTHORIZATION "Authorization"
#define HEADER_CONTENT_DISPOSITION "Content-Disposition"
#define HEADER_ETAG "ETag"

#define CONTENT_DISPOSITION_ATTACHMENT "attachment"
#define ERROR_MESSAGE_LENGTH 1024

#define SOCKET_BUFFER_CHUNK 1500
#define SOCKET_TYPE_TCP 1
#define SOCKET_TYPE_UNUX 2

#define AUTH_TYPE_JWT "jwt"
#define AUTH_TYPE_SESSION "session"

#define REQUEST_TYPE_JSON "json"
#define REQUEST_TYPE_MONGO "mongo"
#define REQUEST_TYPE_MYSQL "mysql"
#define REQUEST_TYPE_ORACLE "oracle"
#define REQUEST_TYPE_XML "xml"

#define TRANSPORT_TYPE_HTTP "http"
#define TRANSPORT_TYPE_MONGO "mongo"
#define TRANSPORT_TYPE_MYSQL "mysql"
#define TRANSPORT_TYPE_ORACLE "oracle"
#define TRANSPORT_TYPE_TCP "tcp"
#define TRANSPORT_TYPE_UNIX "unix"

#define CONTENT_TYPE_MPFD "multipart/form-data"
#define CONTENT_TYPE_AXWFU "application/x-www-form-urlencoded"

// Structures
typedef struct {
	ngx_array_t loc_confs; 		// ngx_http_cdn_conf_t
} ngx_http_cdn_main_conf_t;

typedef struct {
	ngx_str_t server_id;
	ngx_str_t fs_root;
	ngx_str_t fs_depth;
	ngx_str_t request_type;
	ngx_str_t transport_type;
	ngx_str_t unix_socket;
	ngx_str_t tcp_host;
	ngx_str_t tcp_port;
	ngx_str_t auth_cookie;
	ngx_str_t auth_header;
	ngx_str_t auth_type;
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
	ngx_str_t cors_origin;
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
} metadata_t;

typedef struct {
	char *name;
	char *value;
} cdn_kvp_t;

typedef struct {
	ngx_http_request_t *r;
	time_t exp;
	uint server_id;
	uint fs_depth;
	char *fs_root;
	char *http_method;
	char *request_type;
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
	const char *auth_value;
	char *auth_request;
	char *auth_response;
	int auth_response_len;
	int auth_response_pos;
	char *jwt_key;
	char *jwt_json;
	char *jwt_field;
	char *db_dsn;
	char *sql_query;
	char *hdr_if_none_match;
	time_t hdr_if_modified_since;
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
#endif
#ifdef CDN_ENABLE_MYSQL
	MYSQL_RES *mysql_result;
#endif
#ifdef CDN_ENABLE_ORACLE
    OCI_Connection *oracle_connection;
    OCI_Statement *oracle_statement;
	OCI_Resultset *oracle_result;
#endif
} session_t;

typedef struct {
	char *host;
	char *port_str;
	int port;
	char *socket;
	char *user;
	char *password;
	char *db;
} db_dsn_t;

enum {
	METADATA_NONE = 0,
	METADATA_SELECT,
	METADATA_DELETE,
	METADATA_INSERT
};

enum {
	UPLOAD_CONTENT_TYPE_NONE = 0,
	UPLOAD_CONTENT_TYPE_MPFD,
	UPLOAD_CONTENT_TYPE_AXWFU,
};

