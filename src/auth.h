/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

// JWT
ngx_int_t auth_jwt(session_t *session, ngx_http_request_t *r);

// Session
ngx_int_t auth_session(session_t *session, ngx_http_request_t *r);

