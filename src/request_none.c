/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "utils.h"

/**
 * Prepare None request GET
 */
ngx_int_t request_get_none(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	return NGX_OK;
}

/**
 * Prepare None request POST
 */
ngx_int_t request_post_none(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	return NGX_OK;
}

/**
 * Process None response GET
 */
ngx_int_t response_get_none(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	return NGX_OK;
}

/**
 * Process None response POST
 */
ngx_int_t response_post_json(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	return NGX_OK;
}

