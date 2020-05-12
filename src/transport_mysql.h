/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

// Prototypes
ngx_int_t transport_mysql(session_t *session, ngx_http_request_t *r, int mode);
