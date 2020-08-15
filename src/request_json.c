/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "utils.h"

/**
 * Prepare JSON request GET
 */
ngx_int_t request_get_json(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	int i;
	char s[11];
	bson_t b, bc, bh, bel;

	// Init a BSON
	bson_init (&b);

	// Add the file ID
	BSON_APPEND_UTF8 (&b, "file_id", metadata->file);

	// Add HTTP method
	BSON_APPEND_UTF8 (&b, "http_method", session->http_method);

	// Add the authorisation key as extracted from JWT
	if (session->auth_value)
		BSON_APPEND_UTF8 (&b, "auth_value", session->auth_value);

	// Headers: make an array of objects with name and value
	if (! strcmp(session->all_headers, "yes")) {
		BSON_APPEND_ARRAY_BEGIN(&b, "headers", &bh);
		for (i=0; i < session->headers_count; i++) {
			sprintf(&s[0],"%d", i);
			BSON_APPEND_DOCUMENT_BEGIN(&bh, &s[0], &bel);
			BSON_APPEND_UTF8 (&bel, "name", session->headers[i].name);
			BSON_APPEND_UTF8 (&bel, "value", session->headers[i].value);
			bson_append_document_end (&bh, &bel);
		}
		bson_append_array_end (&b, &bh);
	}

	// Cookies: make an array of objects with name and value
	if (! strcmp(session->all_cookies, "yes")) {
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

	session->auth_request = bson_as_json (&b, NULL);

	bson_destroy(&b);

	return NGX_OK;
}

/**
 * Prepare JSON request POST
 */
ngx_int_t request_post_json(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	bson_t doc;

	// Init a BSON
	bson_init (&doc);

	// Add the values
	BSON_APPEND_UTF8 (&doc, "http_method", session->http_method);
	BSON_APPEND_UTF8 (&doc, "file_id", metadata->file);
	BSON_APPEND_UTF8 (&doc, "filename", metadata->filename);
	BSON_APPEND_UTF8 (&doc, "content_type", metadata->content_type);
	BSON_APPEND_UTF8 (&doc, "content_disposition", metadata->content_disposition);
	BSON_APPEND_UTF8 (&doc, "etag", metadata->etag);

	if (session->auth_value)
		BSON_APPEND_UTF8 (&doc, "auth_value", session->auth_value);

	session->auth_request = bson_as_json (&doc, NULL);

	bson_destroy(&doc);

	return NGX_OK;
}

/**
 * Process JSON response GET
 */
ngx_int_t response_get_json(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	bson_t doc;
	bson_error_t error;
	bson_iter_t iter;
	const char *bson_key;
	ngx_int_t ret;

	// If we got no repsonse, skip processing
	if (! session->auth_response) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "No authorisation response received, skipping JSON processing");
		return NGX_OK;
	}

	// Walk around the JSON which we received from the authentication server, session->auth_response
	if (! bson_init_from_json(&doc, session->auth_response, strlen(session->auth_response), &error)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to parse JSON (%s): %s", error.message, session->auth_response);
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
			if ((ret = set_metadata_field(r, &metadata->filename, "filename", bson_iter_utf8 (&iter, NULL))) > 0)
				return ret;
		}

		else if ((! strcmp(bson_key, "auth_value")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			if ((ret = set_metadata_field(r, &metadata->auth_value, "auth_value", bson_iter_utf8 (&iter, NULL))) > 0)
				return ret;
		}

		else if ((! strcmp(bson_key, "error")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			if ((ret = set_metadata_field(r, &metadata->error, "error", bson_iter_utf8 (&iter, NULL))) > 0)
				return ret;
		}

		else if ((! strcmp(bson_key, "content_type")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			if ((ret = set_metadata_field(r, &metadata->content_type, "content_type", bson_iter_utf8 (&iter, NULL))) > 0)
				return ret;
		}

		else if ((! strcmp(bson_key, "content_disposition")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			if ((ret = set_metadata_field(r, &metadata->content_disposition, "content_disposition", bson_iter_utf8 (&iter, NULL))) > 0)
				return ret;
		}

		else if ((! strcmp(bson_key, "etag")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			if ((ret = set_metadata_field(r, &metadata->etag, "etag", bson_iter_utf8 (&iter, NULL))) > 0)
				return ret;
		}

		else if ((! strcmp(bson_key, "status")) && (bson_iter_type(&iter) == BSON_TYPE_INT32)) {
			metadata->status = bson_iter_int32 (&iter);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata status: %l", metadata->status);
		}
	}

	bson_destroy(&doc);

	session->auth_response_count = 1;

	// Do an authorisation check if the response has come from a local source (like Internal or Redis transport)
	auth_check(session, metadata, r);

	return NGX_OK;
}

/**
 * Process JSON response POST
 */
ngx_int_t response_post_json(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	bson_t doc;
	bson_error_t error;
	bson_iter_t iter;
	const char *bson_key;

	// If we got no repsonse, skip processing
	if (! session->auth_response) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "No authorisation response received, skipping JSON processing");
		return NGX_OK;
	}

	// Walk around the JSON which we received from the authentication server, session->auth_response
	if (! bson_init_from_json(&doc, session->auth_response, strlen(session->auth_response), &error)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to parse JSON (%s): %s", error.message, session->auth_response);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (! bson_iter_init (&iter, &doc)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to initialise BSON iterator");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	while(bson_iter_next(&iter)) {
		bson_key = bson_iter_key (&iter);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing metadata key %s with type %i", bson_key, bson_iter_type(&iter));

		if ((! strcmp(bson_key, "status")) && (bson_iter_type(&iter) == BSON_TYPE_INT32)) {
			metadata->status = bson_iter_int32 (&iter);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata status: %l", metadata->status);
		}
	}

	bson_destroy(&doc);

	session->auth_response_count = 1;

	// Do an authorisation check if the response has come from a local source (like Internal or Redis transport)
	auth_check(session, metadata, r);

	return NGX_OK;
}

