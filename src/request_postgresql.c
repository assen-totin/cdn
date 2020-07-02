/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "utils.h"

/**
 * Process postgresql response GET
 */
ngx_int_t response_get_postgresql(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
#ifdef CDN_ENABLE_POSTGRESQL
	int i;
	ngx_int_t ret;

	// NB: we only expect one row in response, but empty may also be OK (depending on default HTTP status code)
	if (session->postgresql_result) {
		if (PQresultStatus(session->postgresql_result) == PGRES_TUPLES_OK) {
			session->auth_response_count = 1;

			for (i = 0; i < PQnfields(session->postgresql_result); i++) {
				// Handle NULL values
				if (! PQgetvalue(session->postgresql_result, 0, i))
					continue;

				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing metadata key %s with length", PQfname(session->postgresql_result, i));

				if (! strcmp(PQfname(session->postgresql_result, i), "filename")) {
					if ((ret = set_metadata_field(r, &metadata->filename, "filename", PQgetvalue(session->postgresql_result, 0, i))) > 0)
						return ret;
				}

				else if (! strcmp(PQfname(session->postgresql_result, i), "error"))  {
					if ((ret = set_metadata_field(r, &metadata->error, "error", PQgetvalue(session->postgresql_result, 0, i))) > 0)
						return ret;
				}

				else if (! strcmp(PQfname(session->postgresql_result, i), "content_type"))  {
					if ((ret = set_metadata_field(r, &metadata->content_type, "content_type", PQgetvalue(session->postgresql_result, 0, i))) > 0)
						return ret;
				}

				else if (! strcmp(PQfname(session->postgresql_result, i), "content_disposition"))  {
					if ((ret = set_metadata_field(r, &metadata->content_disposition, "content_disposition", PQgetvalue(session->postgresql_result, 0, i))) > 0)
						return ret;
				}

				else if (! strcmp(PQfname(session->postgresql_result, i), "etag"))  {
					if ((ret = set_metadata_field(r, &metadata->etag, "etag", PQgetvalue(session->postgresql_result, 0, i))) > 0)
						return ret;
				}

				else if (! strcmp(PQfname(session->postgresql_result, i), "status")) {
					metadata->status = atol(PQgetvalue(session->postgresql_result, 0, i));
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata status: %l", metadata->status);
				}

				else if (! strcmp(PQfname(session->postgresql_result, i), "length")) {
					metadata->length = atol(PQgetvalue(session->postgresql_result, 0, i));
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata length: %l", metadata->length);
				}

				else if (! strcmp(PQfname(session->postgresql_result, i), "upload_date")) {
					metadata->upload_date = atol(PQgetvalue(session->postgresql_result, 0, i));
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata upload_date: %l", metadata->upload_date);
				}
			}
		}

		// Clear query and disconnect
		PQclear(session->postgresql_result);
	}

	if (session->postgresql_connection)
		PQfinish(session->postgresql_connection);

	session->postgresql_connection = NULL;
	session->postgresql_result = NULL;
#endif

	return NGX_OK;
}


/**
 * Process postgresql response POST
 */
ngx_int_t response_post_postgresql(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
#ifdef CDN_ENABLE_POSTGRESQL
	int i;
	ngx_int_t ret;

	// NB: we only expect one row in response, but empty may also be OK (depending on default HTTP status code)
	if (session->postgresql_result) {
		if (PQresultStatus(session->postgresql_result) == PGRES_TUPLES_OK) {
			session->auth_response_count = 1;

			for (i = 0; i < PQnfields(session->postgresql_result); i++) {
				// Handle NULL values
				if (! PQgetvalue(session->postgresql_result, 0, i))
					continue;

				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing metadata key %s with length", PQfname(session->postgresql_result, i));

				if (! strcmp(PQfname(session->postgresql_result, i), "status")) {
					metadata->status = atol(PQgetvalue(session->postgresql_result, 0, i));
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata status: %l", metadata->status);
				}
			}
		}

		// Clear query and disconnect
		PQclear(session->postgresql_result);
	}

	if (session->postgresql_connection)
		PQfinish(session->postgresql_connection);

	session->postgresql_connection = NULL;
	session->postgresql_result = NULL;
#endif

	return NGX_OK;
}

