#include "common.h"
#include "utils.h"

/**
 * Helper: Set metadata field from JSON value
 */
static inline ngx_int_t set_metadata_json (ngx_http_request_t *r, char **field, char *field_name, const char *value) {
	char *f;

	f = ngx_pcalloc(r->pool, strlen(value) + 1);
	if (f == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata %s.", field_name, strlen(value) + 1);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	strcpy(f, value);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata %s: %s", field_name, f);

	*field = f;

	return NGX_OK;
}

/**
 * Extract all cookies from headers
 */
static ngx_int_t get_cookies(session_t *session, ngx_http_request_t *r) {
	int i, j, cookie_index = -1;
	char *s0, *s1, *s2;
	char *str1, *str2, *token, *subtoken, *saveptr1, *saveptr2;
	char *cookie_delim = " ", *cookie_subdelim = "=";
	ngx_table_elt_t **elts;
	cdn_kvp_t *cookies;

	if (! r->headers_in.cookies.nelts) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "No cookies found");
		return NGX_OK;
	}

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found a total of %l Cookie header", r->headers_in.cookies.nelts);
	elts = r->headers_in.cookies.elts;
	session->cookies_count = r->headers_in.cookies.nelts;

	// Allocate initial memory we have at least r->headers_in.cookies.nelts, but may be more)
	session->cookies = ngx_pnalloc(r->pool, sizeof(cdn_kvp_t) * r->headers_in.cookies.nelts);
	if (session->cookies == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for %l cookies KVP.", sizeof(cdn_kvp_t) * r->headers_in.cookies.nelts, r->headers_in.cookies.nelts);
		return NGX_ERROR;
	}

	for (i=0; i<r->headers_in.cookies.nelts; i++) {
		s0 = from_ngx_str(r->pool, elts[i]->value);
		for (str1 = s0; ; str1 = NULL) {
			token = strtok_r(str1, cookie_delim, &saveptr1);
			if (token == NULL)
				break;

			s1 = strchr(token, ';');
			if (s1 == token + strlen(token) - 1) {
				s2 = ngx_pcalloc(r->pool, strlen(token));
				if (s2 == NULL) {
					ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for cookie token.", strlen(token));
					return NGX_ERROR;
				}
				strncpy(s2, token, strlen(token) - 1);
			}
			else
				s2 = token;

			// Check to see if we have space to accommodate the cookie
			cookie_index ++;
			if (cookie_index == session->cookies_count) {
				cookies = ngx_pnalloc(r->pool, sizeof(cdn_kvp_t) * (session->cookies_count + 1));
				if (session->cookies == NULL) {
					ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for %l cookies KVP.", sizeof(cdn_kvp_t) * (session->cookies_count + 1), session->cookies_count + 1);
					return NGX_ERROR;
				}
				memcpy(cookies, session->cookies, sizeof(cdn_kvp_t) * session->cookies_count);
				session->cookies = cookies;
			}
			session->cookies_count ++;

			// Extract the cookie
			for (j=0, str2 = s2; ; j++, str2 = NULL) {
				subtoken = strtok_r(str2, cookie_subdelim, &saveptr2);
				if (subtoken == NULL)
					break;

				if (j == 0) {
					session->cookies[cookie_index].name = ngx_pcalloc(r->pool, strlen(subtoken) + 1);
					if (session->cookies[cookie_index].name == NULL) {
						ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for cookie name.", strlen(subtoken) + 1);
						return NGX_ERROR;
					}
					strcpy(session->cookies[cookie_index].name, subtoken);
				}
				else if (j == 1) {
					session->cookies[cookie_index].value = ngx_pcalloc(r->pool, strlen(subtoken) + 1);
					if (session->cookies[cookie_index].value == NULL) {
						ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for cookie value.", strlen(subtoken) + 1);
						return NGX_ERROR;
					}
					strcpy(session->cookies[cookie_index].value, subtoken);
				}
				else
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Malformed cookie %s", s0);
			}

			if (j == 2) {
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found cookie %s with value %s", session->cookies[cookie_index].name, session->cookies[cookie_index].value);
			}
		}
	}

	return NGX_OK;
}

/**
 * Prepare JSON request
 */
ngx_int_t request_json(session_t *session, ngx_http_request_t *r) {
	int i;
	char s[11];
	bson_t b, bc, bh, bel;
	ngx_int_t ret;

	// Init a BSON
	bson_init (&b);

	// Add the URI
	BSON_APPEND_UTF8 (&b, "uri", session->uri);

	// Add the authorisation key as extracted from JWT
	if (session->jwt_value)
		BSON_APPEND_UTF8 (&b, "jwt_value", session->jwt_value);

	// Headers: make an array of objects with name and value
	if (! strcmp(session->json_extended, "yes")) {
		BSON_APPEND_ARRAY_BEGIN(&b, "headers", &bh);
		for (i=0; i < session->headers_count; i++) {
			sprintf(&s[0],"%d", i);
			BSON_APPEND_DOCUMENT_BEGIN(&bh, &s[0], &bel);
			BSON_APPEND_UTF8 (&bel, "name", session->headers[i].name);
			BSON_APPEND_UTF8 (&bel, "value", session->headers[i].value);
			bson_append_document_end (&bh, &bel);
		}
		bson_append_array_end (&b, &bh);

		// Extract all cookies
		ret = get_cookies(session, r);
		if (ret)
			return ret;

		// Cookies: make an array of objects with name and value
		BSON_APPEND_ARRAY_BEGIN(&b, "cookies", &bc);
		for (i=0; i < session->cookies_count; i++) {
			sprintf(&s[0],"%d", i);
			BSON_APPEND_DOCUMENT_BEGIN(&bc, &s[0], &bel);
			BSON_APPEND_UTF8 (&bel, "name", session->cookies[i].name);
			BSON_APPEND_UTF8 (&bel, "value", session->cookies[i].value);
			bson_append_document_end (&bc, &bel);
		}
		bson_append_array_end (&b, &bc);
	}

	session->unix_request = bson_as_json (&b, NULL);

	bson_destroy(&b);

	return NGX_OK;
}

/**
 * Process JSON response
 */
ngx_int_t response_json(session_t *session, cdn_file_t *metadata, ngx_http_request_t *r) {
	bson_t doc;
	bson_error_t error;
	bson_iter_t iter;
	const char *bson_key;
	ngx_int_t ret;

	// Walk around the JSON which we received from the authentication servier, session->unix_response
	if (! bson_init_from_json(&doc, session->unix_response, strlen(session->unix_response), &error)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to parse JSON (%s): %s", error.message, session->unix_response);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (! bson_iter_init (&iter, &doc)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to initialise BSON iterator");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	while(bson_iter_next(&iter)) {
		bson_key = bson_iter_key (&iter);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing metadata key %s with type %i", bson_key, bson_iter_type(&iter));

		if ((! strcmp(bson_key, "filename")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			if ((ret = set_metadata_json(r, &metadata->filename, "filename", bson_iter_utf8 (&iter, NULL))) > 0)
				return ret;
		}

		else if ((! strcmp(bson_key, "error")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			if ((ret = set_metadata_json(r, &metadata->error, "error", bson_iter_utf8 (&iter, NULL))) > 0)
				return ret;
		}

		else if ((! strcmp(bson_key, "content_type")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			if ((ret = set_metadata_json(r, &metadata->content_type, "content_type", bson_iter_utf8 (&iter, NULL))) > 0)
				return ret;
		}

		else if ((! strcmp(bson_key, "content_disposition")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			if ((ret = set_metadata_json(r, &metadata->content_disposition, "content_disposition", bson_iter_utf8 (&iter, NULL))) > 0)
				return ret;
		}

		else if ((! strcmp(bson_key, "etag")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			if ((ret = set_metadata_json(r, &metadata->etag, "etag", bson_iter_utf8 (&iter, NULL))) > 0)
				return ret;
		}

		else if ((! strcmp(bson_key, "status")) && (bson_iter_type(&iter) == BSON_TYPE_INT32)) {
			metadata->status = bson_iter_int32 (&iter);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata status: %l", metadata->status);
		}

		else if (! strcmp(bson_key, "length")) {
			if (bson_iter_type(&iter) == BSON_TYPE_INT32)
				metadata->length = bson_iter_int32 (&iter);
			else if (bson_iter_type(&iter) == BSON_TYPE_INT64)
				metadata->length = bson_iter_int64 (&iter);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata length: %l", metadata->length);
		}

		else if ((! strcmp(bson_key, "upload_date")) && (bson_iter_type(&iter) == BSON_TYPE_DATE_TIME)) {
			metadata->upload_date = bson_iter_date_time (&iter);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata upload_date: %l", metadata->upload_date);
		}
	}

	bson_destroy(&doc);

	return NGX_OK;
}

