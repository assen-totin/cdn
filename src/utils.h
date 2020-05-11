// utils.c
char *memstr(char *haystack, char *needle, int size);
char *from_ngx_str(ngx_pool_t *pool, ngx_str_t ngx_str);
ngx_int_t set_metadata_field (ngx_http_request_t *r, char **field, char *field_name, const char *value);
ngx_int_t get_all_headers(session_t *session, ngx_http_request_t *r);
ngx_int_t get_all_cookies(session_t *session, ngx_http_request_t *r);
ngx_int_t parse_dsn(session_t *session, ngx_http_request_t *r, db_dsn_t *dsn);
ngx_int_t get_path(session_t *session, metadata_t *metadata, ngx_http_request_t *r);


