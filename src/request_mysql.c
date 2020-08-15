/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "utils.h"

/**
 * Process MySQL response GET
 */
ngx_int_t response_get_mysql(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
#ifdef CDN_ENABLE_MYSQL
	int i, fields_num;
	MYSQL_FIELD *fields;
	MYSQL_ROW mysql_row;
	ngx_int_t ret;

	// NB: we only expect one row in response; no rows may be OK still (depending on the selected default HTTP code), so return
	if (! session->mysql_result)
		return NGX_OK;

	mysql_row = mysql_fetch_row(session->mysql_result);
	fields_num = mysql_num_fields(session->mysql_result);
	fields = mysql_fetch_fields(session->mysql_result);

	if (mysql_row) {
		session->auth_response_count = 1;

		for(i = 0; i < fields_num; i++) {
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing metadata key %s with length %l", fields[i].name, fields[i].length);

			// Handle NULL values
			if (! mysql_row[i])
				continue;

			if (! strcmp(fields[i].name, "filename")) {
				if ((ret = set_metadata_field(r, &metadata->filename, "filename", mysql_row[i])) > 0)
					return ret;
			}

			else if (! strcmp(fields[i].name, "error"))  {
				if ((ret = set_metadata_field(r, &metadata->error, "error", mysql_row[i])) > 0)
					return ret;
			}

			else if (! strcmp(fields[i].name, "content_type"))  {
				if ((ret = set_metadata_field(r, &metadata->content_type, "content_type", mysql_row[i])) > 0)
					return ret;
			}

			else if (! strcmp(fields[i].name, "content_disposition"))  {
				if ((ret = set_metadata_field(r, &metadata->content_disposition, "content_disposition", mysql_row[i])) > 0)
					return ret;
			}

			else if (! strcmp(fields[i].name, "etag"))  {
				if ((ret = set_metadata_field(r, &metadata->etag, "etag", mysql_row[i])) > 0)
					return ret;
			}

			else if (! strcmp(fields[i].name, "status")) {
				metadata->status = atol(mysql_row[i]);
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata status: %l", metadata->status);
			}
		}
	}

	mysql_free_result(session->mysql_result);
#endif

	return NGX_OK;
}


/**
 * Process MySQL response POST
 */
ngx_int_t response_post_mysql(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
#ifdef CDN_ENABLE_MYSQL
	int i, fields_num;
	MYSQL_FIELD *fields;
	MYSQL_ROW mysql_row;
	ngx_int_t ret;

	// NB: we only expect one row in response or no rows
	if (! session->mysql_result)
		return NGX_OK;

	mysql_row = mysql_fetch_row(session->mysql_result);
	fields_num = mysql_num_fields(session->mysql_result);
	fields = mysql_fetch_fields(session->mysql_result);

	if (mysql_row) {
		session->auth_response_count = 1;

		for(i = 0; i < fields_num; i++) {
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing metadata key %s with length %l", fields[i].name, fields[i].length);

			// Handle NULL values
			if (! mysql_row[i])
				continue;

			if (! strcmp(fields[i].name, "status")) {
				metadata->status = atol(mysql_row[i]);
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata status: %l", metadata->status);
			}
		}
	}

	mysql_free_result(session->mysql_result);
#endif

	return NGX_OK;
}

