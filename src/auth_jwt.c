/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"

#ifdef CDN_ENABLE_JWT
/**
 * Callback for JWT checker
 */
int auth_jwt_callback(jwt_t *jwt, jwt_config_t *config) {
	jwt_value_error_t ret;
	jwt_value_t val_cust, val_exp;
	jwt_ctx_t *ctx = (jwt_ctx_t *) config->ctx;

	session_t *session = ctx->session;
	ngx_http_request_t *r = ctx->r;

	// Check the exp claim in the JWT
	jwt_set_GET_INT(&val_exp, "exp");
	if ((ret = jwt_claim_get (jwt, &val_exp))) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to get claim exp", session->auth_token);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	if (! val_exp.int_val) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to find claim exp", session->auth_token);
		return NGX_HTTP_UNAUTHORIZED;
	}

	if (val_exp.int_val < time(NULL)) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Token %s has expired", session->auth_token);
		return NGX_HTTP_UNAUTHORIZED;
	}
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Token is OK");

	// Get the custom claim from the JWT
	jwt_set_GET_STR(&val_cust, session->jwt_field);
	if ((ret = jwt_claim_get (jwt, &val_cust))) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to find claim %s", session->auth_token, session->jwt_field);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (! val_cust.str_val) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to find claim %s", session->auth_token, session->jwt_field);
		return NGX_HTTP_UNAUTHORIZED;
	}

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Token %s found claim %s %s", session->auth_token, session->jwt_field, val_cust.str_val);
	if ((session->auth_value = ngx_pcalloc(r->pool, strlen(val_cust.str_val) + 1 )) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for for auth_value.", strlen(val_cust.str_val));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	strcpy(session->auth_value, val_cust.str_val);

	return 0;
}
#endif

/**
 * Extract JWT
 */
ngx_int_t auth_jwt(session_t *session, ngx_http_request_t *r) {
#ifdef CDN_ENABLE_JWT
	const char *error;
	jwt_checker_t *checker;
	jwt_ctx_t ctx;
	jwk_item_t *key;
	jwk_set_t *set;
	ngx_int_t ret;

	checker = jwt_checker_new();
	if (! checker) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to create checker", session->auth_token);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Create JWK from the key string
	set = jwks_create(session->instance->jwt_key);
	if (! set) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s error creating JWK from string", session->auth_token);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	if (jwks_error(set)) {
		error = jwks_error_msg(set);
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s error creating JWK from string: %s", session->auth_token, error);
		jwks_free(set);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Set key (algorithm is derived from the "alg" property of the key)
	if ((ret = jwt_checker_setkey(checker, jwks_item_alg(jwks_item_get(set, 0)), jwks_item_get(set, 0)))) {
		error = jwt_checker_error_msg (checker);
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s error setting JWT key: %s", session->auth_token, error);
		jwt_checker_free (checker);
		jwks_free(set);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Set callback
	ctx.session = session;
	ctx.r = r;

	if ((ret = jwt_checker_setcb (checker, &auth_jwt_callback, (void *) &ctx))) {
		error = jwt_checker_error_msg (checker);
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s error setting JWT key: %s", session->auth_token, error);
		jwt_checker_free (checker);
		jwks_free(set);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Verify signature (this will also sun the callback before verifying the signature)
	if ((ret = jwt_checker_verify(checker, session->auth_token))) {
		error = jwt_checker_error_msg (checker);
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s error verifying %s", session->auth_token, error);
		jwt_checker_free (checker);
		jwks_free(set);
		return NGX_HTTP_UNAUTHORIZED;
	}

	jwt_checker_free (checker);
	jwks_free(set);
#endif

	return NGX_OK;
}

