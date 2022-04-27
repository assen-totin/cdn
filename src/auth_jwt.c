/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"

/**
 * Extract JWT
 */
ngx_int_t auth_jwt(session_t *session, ngx_http_request_t *r) {
#ifdef CDN_ENABLE_JWT
	time_t exp;
	ngx_int_t ret;
	const char *auth_value;

	// If auth token was not found, give up
	if (! session->auth_token) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Auth token not found, declining request");
		return NGX_HTTP_UNAUTHORIZED;
	}

	// Validate and extract the token
	if ((ret = jwt_decode(&session->jwt, session->auth_token, (unsigned char*)session->instance->jwt_key, strlen(session->instance->jwt_key)))) {
		jwt_free(session->jwt);

		if (ret == EINVAL) {
			// Invalid signature
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s invalid signature", session->auth_token);
			return NGX_HTTP_UNAUTHORIZED;
		}
		else {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s system error %u while decoding", session->auth_token, ret);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	// Check expiration
	exp = jwt_get_grant_int(session->jwt, "exp");
	if (errno == ENOENT) {
		jwt_free(session->jwt);
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to find claim EXP", session->auth_token);
		return NGX_HTTP_UNAUTHORIZED;
	}
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Token %s found claim EXP %l", session->auth_token, exp);
	if (exp < time(NULL)) {
		jwt_free(session->jwt);
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s has expired: EXP is %l, now is %l", session->auth_token, exp, time(NULL));
		return NGX_HTTP_UNAUTHORIZED;
	}

	// Extract the value from payload that we'll use in authentication
	auth_value = jwt_get_grant(session->jwt, session->jwt_field);
	if (auth_value) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Token %s found claim %s %s", session->auth_token, session->jwt_field, auth_value);
		if ((session->auth_value = ngx_pcalloc(r->pool, strlen(auth_value) + 1 )) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for for auth_value.", strlen(auth_value));
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		strcpy(session->auth_value, auth_value);
	}
	else {
		jwt_free(session->jwt);
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to find claim %s", session->auth_token, session->jwt_field);
		return NGX_HTTP_UNAUTHORIZED;
	}

	jwt_free(session->jwt);
#endif

	return NGX_OK;
}

