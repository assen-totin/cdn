/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

// Prototypes
ngx_int_t request_get_xml(session_t *session, metadata_t *metadata, ngx_http_request_t *r);
ngx_int_t request_post_xml(session_t *session, metadata_t *metadata, ngx_http_request_t *r);
ngx_int_t response_get_xml(session_t *session, metadata_t *meta_file, ngx_http_request_t *r);
ngx_int_t response_post_xml(session_t *session, metadata_t *meta_file, ngx_http_request_t *r);

