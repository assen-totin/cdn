/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "utils.h"

/**
 * Pre-auth metadata
 */

/*
NB: 
- Pre-auth only works for downloads (the auth_value must match the file ID)
- No metadata can be extracted, so the file will be served verbatim
*/

ngx_int_t transport_preauth(session_t *session, metadata_t *metadata, ngx_http_request_t *r, int mode) {
	// If auth_value was not given, reject request (this is a pre-auth transport, after all)
	if (! session->auth_value)
		return NGX_HTTP_FORBIDDEN;

	// If auth_value does not match the file ID, reject request
	if (strcmp(session->auth_value, metadata->file16))
		return NGX_HTTP_FORBIDDEN;

	return NGX_OK;
}

