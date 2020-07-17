/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "utils.h"

/**
 * File metadata from redis
 */
ngx_int_t transport_redis(session_t *session, metadata_t *metadata, ngx_http_request_t *r, int mode) {
#ifdef CDN_ENABLE_REDIS
	redisContext *context;
	redisReply *reply;
	ngx_int_t ret;
	struct timeval timeout = {5, 0}; 

	// Connect Redis w/ 5 sec timeout
	if (cdn_globals->dsn->socket) {
		// Connect via Unix socket
		if ((context = redisConnectUnixWithTimeout(cdn_globals->dsn->socket, timeout)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Unable to create Redis context.");
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
	}
	else {
		if ((context = redisConnectWithTimeout(cdn_globals->dsn->host, cdn_globals->dsn->port, timeout)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Unable to create Redis context.");
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	if (context->err) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Error connecting to Redis: %s", context->errstr);
		redisFree(context);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Save, delete or read metadata
	if (mode == METADATA_INSERT) {
		// Save metadata to Redis
		if ((reply = redisCommand(context, "SET %s %s", metadata->file, session->auth_request)) == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Redis transport: failed to write metadata %s for file %s: %s", session->auth_request, metadata->file, context->errstr);
			freeReplyObject(reply);
			redisFree(context);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		redisFree(context);
	}

	else if (mode == METADATA_DELETE) {
		// Delete metadata to Redis
		if ((reply = redisCommand(context, "DEL %s", metadata->file)) == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Redis transport: failed to delete metadata for file %s: %s", metadata->file, context->errstr);
			freeReplyObject(reply);
			redisFree(context);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		redisFree(context);
	}

	else {
		// Read metadata
		if ((reply = redisCommand(context, "GET %s", metadata->file)) == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Redis transport: failed to read metadata for file %s: %s", metadata->file, context->errstr);
			redisFree(context);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		// Check for error
		if (reply->type == REDIS_REPLY_ERROR) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Redis transport: error reading metadata for file %s: %s", metadata->file, reply->str);
			freeReplyObject(reply);
			redisFree(context);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		// Check for empty response (key not found)
		if (reply->type == REDIS_REPLY_NIL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Redis transport: empty respnse while  reading metadata for file %s", metadata->file);
			freeReplyObject(reply);
			redisFree(context);
			return NGX_OK;
		}

		// Prepare buffer to read the file
		if ((session->auth_response = ngx_pcalloc(r->pool, strlen(reply->str) + 1)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata filename.", strlen(reply->str) + 1);
			freeReplyObject(reply);
			redisFree(context);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		strcpy(session->auth_response, reply->str);

		freeReplyObject(reply);
		redisFree(context);
	}
#endif

	return NGX_OK;
}

