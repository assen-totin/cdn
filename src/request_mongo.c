/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"

/**
 * Prepare Mongo auth request for GET
 */
ngx_int_t request_get_mongo(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	bson_t filter;

	// Prepare filter for query
	bson_init (&filter);
	BSON_APPEND_UTF8 (&filter, "file_id", metadata->file);

	if (session->auth_value)
		BSON_APPEND_UTF8 (&filter, "auth_value", session->auth_value);

	session->auth_request = bson_as_canonical_extended_json(&filter, NULL);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Using BSON filter: %s", session->auth_request);

	bson_destroy(&filter);

	return NGX_OK;
}

/**
 * Prepare Mongo auth request for POST
 */
ngx_int_t request_post_mongo(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	bson_t doc;

	// Prepare filter for query
	bson_init (&doc);
	BSON_APPEND_UTF8 (&doc, "file_id", metadata->file);
	BSON_APPEND_UTF8 (&doc, "filename", metadata->filename);
	BSON_APPEND_INT32 (&doc, "length", metadata->length);
	BSON_APPEND_UTF8 (&doc, "content_type", metadata->content_type);
	BSON_APPEND_UTF8 (&doc, "content_disposition", metadata->content_disposition);
	BSON_APPEND_TIME_T (&doc, "upload_date", metadata->upload_date);
	BSON_APPEND_UTF8 (&doc, "etag", metadata->etag);

	if (session->auth_value)
		BSON_APPEND_UTF8 (&doc, "auth_value", session->auth_value);

	session->auth_request = bson_as_canonical_extended_json(&doc, NULL);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Using BSON doc: %s", session->auth_request);

	bson_destroy(&doc);

	return NGX_OK;
}


