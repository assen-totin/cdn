#include "common.h"
#include "utils.h"

/**
 * Helper: Mongo error handler
 */
static ngx_int_t close_mongo(mongoc_client_t * conn, mongoc_collection_t *collection, ngx_int_t ret) {
#ifdef CDN_ENABLE_MONGO
	mongoc_collection_destroy(collection);
	mongoc_client_destroy(conn);
#endif
	return ret;
}

/**
 * Get file metadata from Mongo
 */
ngx_int_t transport_mongo(session_t *session, ngx_http_request_t *r) {
#ifdef CDN_ENABLE_MONGO
	bson_t *opts, *doc;
	mongoc_client_t * conn;
	mongoc_collection_t *collection;
	ngx_int_t ret;

	// Connect MongoDB
	if ((conn = mongoc_client_new (session->db_dsn)) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to connect to MongoDB");
		cleanup_mongo(&mongo);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Get collection
	collection = mongoc_client_get_collection (conn, session->mongo_db, session->mongo_collection);
	if (! mongo->collection) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to get Mongo collection %s", session->mongo_collection);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Run the query
#ifdef RHEL7
	cursor = mongoc_collection_find (collection, MONGOC_QUERY_NONE, 0, 1, 1, session->auth_request, NULL, NULL);
#endif
#ifdef RHEL8
	opts = BCON_NEW ("limit", BCON_INT64 (1));
	cursor = mongoc_collection_find_with_opts (collection, session->auth_request, NULL, NULL);
	bson_destroy (opts);
#endif
	if (! cursor) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to get cursor for collection %s", session->mongo_collection);
		return close_mongo(conn, collection, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// If nothing was found, the filter did not match, so reject the request
	if (! mongoc_cursor_next (cursor, &doc)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Metadata for file %s not found in collection %s", metadata->file, session->mongo_collection);
		return close_mongo(conn, collection, NGX_HTTP_NOT_FOUND);
	}

	session->mongo_reponse = bson_copy (doc);

	close_mongo(conn, collection, NGX_OK);

#endif

	return NGX_OK;
}

