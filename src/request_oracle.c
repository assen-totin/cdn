#include "common.h"
#include "utils.h"

/**
 * Process Oracle response
 */
ngx_int_t response_oracle(session_t *session, cdn_file_t *metadata, ngx_http_request_t *r) {
#ifdef CDN_TRANSPORT_ORACLE
	ngx_int_t ret;

	// NB: we only expect one row in response
	OCI_FetchNext(session->oracle_result);

	if ((ret = set_metadata_field(r, &metadata->filename, "filename", OCI_GetString2(session->oracle_result, "filename"))) > 0)
		return ret;

	if ((ret = set_metadata_field(r, &metadata->error, "error", OCI_GetString2(session->oracle_result, "error"))) > 0)
		return ret;

	if ((ret = set_metadata_field(r, &metadata->content_type, "content_type", OCI_GetString2(session->oracle_result, "content_type"))) > 0)
		return ret;

	if ((ret = set_metadata_field(r, &metadata->content_disposition, "content_disposition", OCI_GetString2(session->oracle_result, "content_disposition"))) > 0)
		return ret;

	if ((ret = set_metadata_field(r, &metadata->etag, "etag", OCI_GetString2(session->oracle_result, "etag"))) > 0)
		return ret;

	metadata->status = OCI_GetInt2(session->oracle_result, "status");
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata status: %l", metadata->status);

	metadata->length = OCI_GetBigInt2(session->oracle_result, "length");
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata length: %l", metadata->length);

	metadata->upload_date = OCI_GetInt2(session->oracle_result, "upload_date");
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata upload_date: %l", metadata->upload_date);
#endif

	return NGX_OK;
}

