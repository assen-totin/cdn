/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "utils.h"

/**
 * Helper: Mongo error handler
 */
#ifdef CDN_ENABLE_MONGO
static ngx_int_t close_mongo(bson_t *query,  mongoc_client_t * conn, mongoc_collection_t *collection, ngx_int_t ret) {
	if (query)
		bson_destroy(query);
	if (collection)
		mongoc_collection_destroy(collection);
	if (conn)
		mongoc_client_destroy(conn);
	return ret;
}
#endif

/**
 * Get file metadata from Mongo
 */
ngx_int_t transport_mongo(session_t *session, ngx_http_request_t *r, int mode) {
#ifdef CDN_ENABLE_MONGO
	const bson_t *doc;
	bson_t *query;
	bson_error_t error;
	mongoc_client_t *conn;
	mongoc_collection_t *collection = NULL;
	mongoc_cursor_t *cursor;

	// Prepare the query
	if ((query = bson_new_from_json((const unsigned char *) session->auth_request, -1, &error)) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to process JSON->BSON auth_request %s: %s", session->auth_request, &error.message[0]);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Connect MongoDB
	if ((conn = mongoc_client_new (session->db_dsn)) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to connect to MongoDB");
		return close_mongo(query, NULL, NULL, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// Get collection
	if ((collection = mongoc_client_get_collection (conn, session->mongo_db, session->mongo_collection)) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to get Mongo collection %s", session->mongo_collection);
		return close_mongo(query, conn, NULL, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// Find document with optional delete after
	if ((mode == METADATA_SELECT) || (mode == METADATA_DELETE)) {
		// Run the query
#ifdef RHEL7
		cursor = mongoc_collection_find (collection, MONGOC_QUERY_NONE, 0, 1, 1, query, NULL, NULL);
#endif
#ifdef RHEL8
		cursor = mongoc_collection_find_with_opts (collection, query, NULL, NULL);
#endif

		if (! cursor) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to get cursor for collection %s", session->mongo_collection);
			return close_mongo(query, conn, collection, NGX_HTTP_INTERNAL_SERVER_ERROR);
		}

		// If nothing was found, the filter did not match, so reject the request
		if (! mongoc_cursor_next (cursor, &doc)) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Metadata not found in collection %s", session->mongo_collection);
			return close_mongo(query, conn, collection, NGX_HTTP_FORBIDDEN);
		}

		// Act as per mode
		if (mode == METADATA_SELECT)
			// If invoked to select data, convert it
			session->auth_response = bson_as_json(doc, NULL);
		else if (mode == METADATA_DELETE)
			// If invoked to delete, ignore error
			if (! mongoc_collection_delete_one (collection, query, NULL, NULL, &error))
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to delete metadata from Mongo collection %s: %s", session->mongo_collection, &error.message[0]);
	}
	// Insert new document
	else if (mode == METADATA_INSERT) {
		if (! mongoc_collection_insert_one (collection, query, NULL, NULL, &error)) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to insert metadata into Mongo collection %s: %s", session->mongo_collection, &error.message[0]);
			return close_mongo(query, conn, collection, NGX_HTTP_INTERNAL_SERVER_ERROR);
		}
	}

	close_mongo(query, conn, collection, NGX_OK);
#endif

	return NGX_OK;
}

