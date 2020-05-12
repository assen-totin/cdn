/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

// Prototypes
ngx_int_t request_get_mongo(session_t *session, metadata_t *metadata, ngx_http_request_t *r);
ngx_int_t request_post_mongo(session_t *session, metadata_t *metadata, ngx_http_request_t *r);

