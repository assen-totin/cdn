/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"

#ifdef CDN_ENABLE_JWT
/**
 * base64url_decode - Base64url decode (following RFC1341)
 * Modified from https://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c
 * Original copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 * Original licence: BSD
 *
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
static inline unsigned char *base64url_decode(const unsigned char *src, size_t len, size_t *out_len) {
	unsigned char dtable[256], *out, *pos, block[4], tmp;
	size_t i, count, olen;
	static const unsigned char base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

	memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++)
		dtable[base64_table[i]] = (unsigned char) i;

	// NB: With Base64url it is customary to NOT have the padding bytes = or == at the end of the string,
	// so we will compenasate for this below
	// NB: We expect the Base64url string to NOT be split with newlines (as may be customary with plain Base64) - 
	// so we will not handle these if they exist

	// Prepare output
	// NB: When padding is missing, the integer division accidentally rounds down the output length to the needed number of bytes
	olen = 3 * len / 4;
	pos = out = malloc(olen);
	if (out == NULL)
		return NULL;

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		block[count] = tmp;
		count++;

		// Auto-pad: if we are at the last byte of input, but the count is not 4, set remaining bytes in the block to 0
		if ((i == (len-1)) && (count < 4)) {
			block[count] = 0;
			count ++;
			if (count < 4) {
				block[count] = 0;
				count ++;
			}
			if (count < 4) {
				// The input is incorrect
				free(out);
				return NULL;
			}
		}

		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
		}
	}

	if (out_len)
		*out_len = pos - out;

	return out;
}
#endif

/**
 * Extract JWT
 */
ngx_int_t auth_jwt(session_t *session, ngx_http_request_t *r) {
#ifdef CDN_ENABLE_JWT
	char *p1, *p2;
	char *hdr_b64u, *pld_b64u, *sig_b64u;
	char *hdr_json, *pld_json, *sig;
	char *tosign;
	char *pld_auth_value_s;
	unsigned char *dig;
	unsigned int hdr_json_len=0, pld_json_len=0, sig_len=0, dig_len=0, alg_type=JWT_ALG_NONE, sig_size=0;
	json_error_t error;
	json_t *hdr, hdr_alg, pld, pld_auth_value;

	// Split the JWT into its three parts: header, payload, signature
	// They are delimited by a dot and each part is separately encoded as Base64url
	p1 = strstr(session->auth_token, ".");
	if (! p1) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to find header: %s", session->auth_token);
		return NGX_HTTP_UNAUTHORIZED;
	}
	if ((hdr_b64u = ngx_pcalloc(r->pool, p1 - session->auth_token + 1 )) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for JWT split", p1 - session->auth_token + 1);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	memcpy(hdr_b64u, session->auth_token, p1 - session->auth_token);

	p1 ++;
	p2 = strstr(p1, ".");
	if (! p2) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to find payload: %s", session->auth_token);
		return NGX_HTTP_UNAUTHORIZED;
	}
	if ((pld_b64u = ngx_pcalloc(r->pool, p2 -p1 + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for JWT split", p2 -p1 + 1);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	memcpy(pld_b64u, p1, p2-p1);

	p2++;
	if ((sig_b64u = ngx_pcalloc(r->pool, session->auth_token + strlen(session->auth_token) - p2 + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for JWT split", session->auth_token + strlen(session->auth_token) - p2 + 1);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	memcpy(sig_b64u, p2, session->auth_token + strlen(session->auth_token) - p2);

	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s header: %s", session->auth_token, hdr_b64u);
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s payload: %s", session->auth_token, pld_b64u);
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s signature: %s", session->auth_token, sig_b64u);

	// Decode Base64URL
	hdr_json = base64url_decode(hdr_b64u, strlen(hdr_b64u), &hdr_json_len);
	if (! hdr_json) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to decode header from base64url: %s", session->auth_token, hdr_b64u);
		return NGX_HTTP_UNAUTHORIZED;
	}

	pld_json = base64url_decode(pld_b64u, strlen(pld_b64u), &pld_json_len);
	if (! pld_json) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to decode payload from base64url: %s", session->auth_token, pld_b64u);
		return NGX_HTTP_UNAUTHORIZED;
	}

	// Parse JSON for header and payload
	hdr = json_loadb(hdr_json, hdr_json_len, 0, &error);
	if (! hdr) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to parse JSON from header: %s", session->auth_token, hdr_json);
		return NGX_HTTP_UNAUTHORIZED;
	}

	pld = json_loadb(pld_json, pld_json_len, 0, &error);
	if (! pld) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to parse JSON from payload: %s", session->auth_token, pld_json);
		return NGX_HTTP_UNAUTHORIZED;
	}

	// Get signature algorithm
	hdr_alg = json_object_get(hdr, "alg");
	if (! hdr_alg) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to find ALG property in header: %s", session->auth_token, hdr_json);
		return NGX_HTTP_UNAUTHORIZED;
	}

	// Decide on expected signature length
	if (strcmp(json_string_value(hdr_alg), "HS256")) {
		alg_type = JWT_ALG_HS256;
		sig_size = 32;		
	}
	else if (strcmp(json_string_value(hdr_alg), "RS256")) {
		alg_type = JWT_ALG_RS256;
		// FIXME: remove comment when algo is implemented below
		//sig_size = 32;
	}
	else if (strcmp(json_string_value(hdr_alg), "ES256")) {
		alg_type = JWT_ALG_ES256;
		// FIXME: remove comment when algo is implemented below
		//sig_size = 32;		
	}

	// Check if we support the signature type
	if (! sig_size) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unsupported signature type: %s", json_string_value(hdr_alg));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Get signature
	sig = base64url_decode(sig_b64u, strlen(sig_b64u), &sig_len);
	if (! sig) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to decode signature from base64url: %s", session->auth_token, sig_b64u);
		return NGX_HTTP_UNAUTHORIZED;
	}

	if (sig_len != sig_size) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to decode signature from base64url (expected %l bytes, got %l): %s", session->auth_token, sig_size, sig_len);
		return NGX_HTTP_UNAUTHORIZED;
	}

	// Create data to be signed: concat the header and payload with a dot
	// NB: The data does not have to be string, but this way we could print it for debug
	if ((tosign = ngx_pcalloc(r->pool, strlen(hdr_b64u) + strlen(pld_b64u) + 2)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for JWT signature data", strlen(hdr_b64u) + strlen(pld_b64u) + 2);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	memcpy(tosign, hdr_b64u, strlen(hdr_b64u));
	memcpy(tosign + strlen(hdr_b64u), ".", 1);
	memcpy(tosign + strlen(hdr_b64u) + 1, pld_b64u, strlen(pld_b64u));
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s data to sign: %s", session->auth_token, tosign);

	// Compute digest
	if ((dig = ngx_pcalloc(r->pool, sig_size )) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for JWT digest", sig_size);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// FIXME: Check here for RS256 and ES256?
	//https://github.com/benmcollins/libjwt/blob/master/libjwt/openssl/sign-verify.c
	switch(alg_type) {
		case JWT_ALG_HS256:
			HMAC(EVP_sha256(), session->instance->jwt_key, strlen(session->instance->jwt_key), tosign, strlen(tosign), dig, &dig_len);
			break;
		//case JWT_ALG_RS256:
		//break;
		//case JWT_ALG_ES256:
		//break;
	}

	if (sig_len != dig_len) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s HMAC length mismatch (wanted %l got %l)", session->auth_token, sig_len, dig_len);
		return NGX_HTTP_UNAUTHORIZED;
	}

	if (memcmp(sig, dig, sig_size) != 0) {
		char *sig_hex = calloc(2*sig_len + 1, 1);
		for (unsigned int i = 0; i < sig_len; i++)
			sprintf(sig_hex + 2*i, "%02hhX", sig[i]);
		char *dig_hex = calloc(2*dig_len + 1, 1);
		for (unsigned int i = 0; i < dig_len; i++)
			sprintf(dig_hex + 2*i, "%02hhX", dig[i]);
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s HMAC mismatch (wanted %s got %s)", session->auth_token, sig_hex, dig_hex);
		free(sig_hex);
		free(dig_hex);
		return NGX_HTTP_UNAUTHORIZED;
	}

	// Get the auth value from the payload of the JWT
	pld_auth_value = json_object_get(pld, session->jwt_field);
	if (! pld_auth_value) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to find claim %s", session->auth_token, session->jwt_field);
		return NGX_HTTP_UNAUTHORIZED;
	}

	pld_auth_value_s = json_string_value(pld_auth_value);
	if (! pld_auth_value_s) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to find claim %s", session->auth_token, session->jwt_field);
		return NGX_HTTP_UNAUTHORIZED;
	}

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Token %s found claim %s: %s", session->auth_token, session->jwt_field, pld_auth_value_s);
	if ((session->auth_value = ngx_pcalloc(r->pool, strlen(pld_auth_value_s) + 1 )) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for auth_value.", strlen(pld_auth_value_s));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	strcpy(session->auth_value, pld_auth_value_s);

	// FIXME: If we return prior to these, we will leak some memory
	free(hdr);
	free(pld);
	free(hdr_json);
	free(pld_json);
#endif

	return NGX_OK;
}

