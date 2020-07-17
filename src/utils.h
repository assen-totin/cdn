/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

// Prototypes
char *memstr(char *haystack, char *needle, int size);
char *from_ngx_str(ngx_pool_t *pool, ngx_str_t ngx_str);
ngx_int_t set_metadata_field (ngx_http_request_t *r, char **field, char *field_name, const char *value);
ngx_int_t get_all_headers(session_t *session, ngx_http_request_t *r);
ngx_int_t get_all_cookies(session_t *session, ngx_http_request_t *r);
ngx_int_t get_path(session_t *session, metadata_t *metadata, ngx_http_request_t *r);
session_t *init_session(ngx_http_request_t *r);
metadata_t *init_metadata(ngx_http_request_t *r);
globals_t *init_globals();
ngx_int_t get_auth_token(session_t *session, ngx_http_request_t *r);
void auth_check(session_t *session, metadata_t *metadata, ngx_http_request_t *r);

