/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

ngx_int_t filter_auth_value(session_t *session, ngx_http_request_t *r);
char *filter_token(ngx_http_request_t *r, char *string, char *delimiter, int pos);

