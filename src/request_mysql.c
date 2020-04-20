#include "common.h"

/**
 * Helper: Set metadata field from MySQL value
 */
static inline ngx_int_t set_metadata_mysql (ngx_http_request_t *r, char **field, char *field_name, char *value) {
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
 * Process MySQL response
 */
ngx_int_t response_mysql(session_t *session, cdn_file_t *metadata, ngx_http_request_t *r) {
	int i, fields_num;
	MYSQL_FIELD *fields;
	MYSQL_ROW mysql_row;
	ngx_int_t ret;

	// NB: we only expect one row in response
	mysql_row = mysql_fetch_row(session->mysql_result);
	fields_num = mysql_num_fields(session->mysql_result);
	fields = mysql_fetch_fields(session->mysql_result);

	for(i = 0; i < fields_num; i++) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing metadata key %s with length %l", fields[i].name, fields[i].length);

		// Handle NULL values
		if (! mysql_row[i])
			continue;

		if (! strcmp(fields[i].name, "filename")) {
			if ((ret = set_metadata_mysql(r, &metadata->filename, "filename", mysql_row[i])) > 0)
				return ret;
		}

		else if (! strcmp(fields[i].name, "error"))  {
			if ((ret = set_metadata_mysql(r, &metadata->error, "error", mysql_row[i])) > 0)
				return ret;
		}

		else if (! strcmp(fields[i].name, "content_type"))  {
			if ((ret = set_metadata_mysql(r, &metadata->content_type, "content_type", mysql_row[i])) > 0)
				return ret;
		}

		else if (! strcmp(fields[i].name, "content_disposition"))  {
			if ((ret = set_metadata_mysql(r, &metadata->content_disposition, "content_disposition", mysql_row[i])) > 0)
				return ret;
		}

		else if (! strcmp(fields[i].name, "etag"))  {
			if ((ret = set_metadata_mysql(r, &metadata->etag, "etag", mysql_row[i])) > 0)
				return ret;
		}

		else if (! strcmp(fields[i].name, "status")) {
			metadata->status = atol(mysql_row[i]);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata status: %l", metadata->status);
		}

		else if (! strcmp(fields[i].name, "length")) {
			metadata->length = atol(mysql_row[i]);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata length: %l", metadata->length);
		}

		else if (! strcmp(fields[i].name, "upload_date")) {
			metadata->upload_date = atol(mysql_row[i]);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata upload_date: %l", metadata->upload_date);
		}
	}

	return NGX_OK;
}

