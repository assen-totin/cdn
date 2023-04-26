/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

/**
 * None metadata
 */
ngx_int_t transport_none(session_t *session, metadata_t *metadata, ngx_http_request_t *r, int mode) {
	return NGX_OK;
}

