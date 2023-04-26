/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

// HTTP
ngx_int_t transport_http(session_t *session, metadata_t *metadata, ngx_http_request_t *r, int mode);

// Internal
ngx_int_t transport_internal(session_t *session, metadata_t *metadata, ngx_http_request_t *r, int mode);

// Mongo
ngx_int_t transport_mongo(session_t *session, metadata_t *metadata, ngx_http_request_t *r, int mode);

// MySQL
ngx_int_t transport_mysql(session_t *session, ngx_http_request_t *r, int mode);

// None
ngx_int_t transport_none(session_t *session, metadata_t *metadata, ngx_http_request_t *r, int mode);

// Oracle
ngx_int_t transport_oracle(session_t *session, ngx_http_request_t *r, int mode);

// PostgreSQL
ngx_int_t transport_postgresql(session_t *session, ngx_http_request_t *r, int mode);

// Redis
ngx_int_t transport_redis(session_t *session, metadata_t *metadata, ngx_http_request_t *r, int mode);

// Socket (Unix, TCP)
ngx_int_t transport_socket(session_t *session, ngx_http_request_t *r, int socket_type);

