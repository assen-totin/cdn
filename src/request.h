/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

// JSON
ngx_int_t request_get_json(session_t *session, metadata_t *metadata, ngx_http_request_t *r);
ngx_int_t request_post_json(session_t *session, metadata_t *metadata, ngx_http_request_t *r);
ngx_int_t response_get_json(session_t *session, metadata_t *meta_file, ngx_http_request_t *r);
ngx_int_t response_post_json(session_t *session, metadata_t *meta_file, ngx_http_request_t *r);

// Mongo
ngx_int_t request_get_mongo(session_t *session, metadata_t *metadata, ngx_http_request_t *r);
ngx_int_t request_post_mongo(session_t *session, metadata_t *metadata, ngx_http_request_t *r);

// MySQL
ngx_int_t response_get_mysql(session_t *session, metadata_t *metadata, ngx_http_request_t *r);
ngx_int_t response_post_mysql(session_t *session, metadata_t *metadata, ngx_http_request_t *r);

// Oracle
ngx_int_t response_get_oracle(session_t *session, metadata_t *metadata, ngx_http_request_t *r);
ngx_int_t response_post_oracle(session_t *session, metadata_t *metadata, ngx_http_request_t *r);

// PostgreSQL
ngx_int_t response_get_postgresql(session_t *session, metadata_t *metadata, ngx_http_request_t *r);
ngx_int_t response_post_postgresql(session_t *session, metadata_t *metadata, ngx_http_request_t *r);

// SQL (common)
ngx_int_t request_get_sql(session_t *session, metadata_t *metadata, ngx_http_request_t *r, int mode);
ngx_int_t request_post_sql(session_t *session, metadata_t *metadata, ngx_http_request_t *r);

// XML
ngx_int_t request_get_xml(session_t *session, metadata_t *metadata, ngx_http_request_t *r);
ngx_int_t request_post_xml(session_t *session, metadata_t *metadata, ngx_http_request_t *r);
ngx_int_t response_get_xml(session_t *session, metadata_t *meta_file, ngx_http_request_t *r);
ngx_int_t response_post_xml(session_t *session, metadata_t *meta_file, ngx_http_request_t *r);

