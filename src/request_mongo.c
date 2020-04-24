#include "common.h"

/**
 * Prepare Mongo request
 */
ngx_int_t request_mongo(session_t *session, cdn_file_t *metadata, ngx_http_request_t *r) {
	bson_t filter;

	// Prepare filter for query
	bson_init (&filter);
	BSON_APPEND_UTF8 (&filter, "file_id", metadata->file);
	BSON_APPEND_UTF8 (&filter, "auth_value", session->auth_value);

	session->auth_request = bson_as_canonical_extended_json(&filter, NULL);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Using BSON filter: %s", session->auth_request);

	bson_destroy(&filter);

	return NGX_OK;
}


