/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

// GET
ngx_int_t cdn_handler_get(ngx_http_request_t *r);

// OPTIONS
ngx_int_t cdn_handler_options (ngx_http_request_t *r);

// POST
void cdn_handler_post (ngx_http_request_t *r);

