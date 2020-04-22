#include "common.h"

/**
 * Extract session ID
 */
ngx_int_t auth_session(session_t *session, ngx_http_request_t *r) {
	// Just copy the token to value
	session->auth_value = session->auth_token;

	return NGX_OK;
}

