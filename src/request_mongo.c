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
#ifdef CDN_ENABLE_MONGO
	bson_t filter;
	bson_error_t error;
	int len;
	char *query;

	// session->mongo_filter now contains the filter template, but we want if to have the expanded filter, so swap it to a local variable
	query = session->mongo_filter;

	// Calculate length for query template + data (this will leave some small overhead from placeholders)
	len = strlen(query);
	len += strlen(metadata->file);
	if (session->auth_value)
		len += strlen(session->auth_value);

	if ((session->mongo_filter = ngx_pcalloc(r->pool, len + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for query.", len + 1);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Replace placehodlers in query
	if (session->auth_value)
		sprintf(session->mongo_filter, query, metadata->file, session->auth_value);
	else
		sprintf(session->mongo_filter, query, metadata->file, "");

	// Prepare filter from query
	bson_init (&filter);
	if (! bson_init_from_json (&filter, session->mongo_filter, -1, &error)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error parsing JSON %s : %s", session->mongo_filter, &error.message[0]);
		bson_destroy(&filter);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Convert back to extended JSON to use later
	session->auth_request = bson_as_canonical_extended_json(&filter, NULL);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Using BSON filter: %s", session->auth_request);

	bson_destroy(&filter);
#endif

	return NGX_OK;
}

/**
 * Prepare Mongo auth request for POST
 */
ngx_int_t request_post_mongo(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
#ifdef CDN_ENABLE_MONGO
	bson_t doc;

	// Prepare filter for query
	bson_init (&doc);
	BSON_APPEND_UTF8 (&doc, "file_id", metadata->file);
	BSON_APPEND_UTF8 (&doc, "filename", metadata->filename);
	BSON_APPEND_UTF8 (&doc, "content_type", metadata->content_type);
	BSON_APPEND_UTF8 (&doc, "content_disposition", metadata->content_disposition);
	BSON_APPEND_UTF8 (&doc, "etag", metadata->etag);

	if (session->auth_value)
		BSON_APPEND_UTF8 (&doc, "auth_value", session->auth_value);

	session->auth_request = bson_as_canonical_extended_json(&doc, NULL);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Using BSON doc: %s", session->auth_request);

	bson_destroy(&doc);
#endif

	return NGX_OK;
}


