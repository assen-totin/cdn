// utils.c
char *from_ngx_str(ngx_pool_t *pool, ngx_str_t ngx_str);
ngx_int_t set_metadata_field (ngx_http_request_t *r, char **field, char *field_name, const char *value);
ngx_int_t get_all_headers(session_t *session, ngx_http_request_t *r);
ngx_int_t get_all_cookies(session_t *session, ngx_http_request_t *r);


