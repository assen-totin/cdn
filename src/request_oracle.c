/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "utils.h"

/**
 * Process Oracle response
 */
ngx_int_t response_get_oracle(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
#ifdef CDN_ENABLE_ORACLE
	ngx_int_t ret;

	// NB: we only expect one row in response
	OCI_FetchNext(session->oracle_result);

	if ((ret = set_metadata_field(r, &metadata->filename, "filename", OCI_GetString2(session->oracle_result, "FILENAME"))) > 0)
		return ret;

	if ((ret = set_metadata_field(r, &metadata->error, "error", OCI_GetString2(session->oracle_result, "ERROR"))) > 0)
		return ret;

	if ((ret = set_metadata_field(r, &metadata->content_type, "content_type", OCI_GetString2(session->oracle_result, "CONTENT_TYPE"))) > 0)
		return ret;

	if ((ret = set_metadata_field(r, &metadata->content_disposition, "content_disposition", OCI_GetString2(session->oracle_result, "CONTENT_DISPOSITION"))) > 0)
		return ret;

	if ((ret = set_metadata_field(r, &metadata->etag, "etag", OCI_GetString2(session->oracle_result, "ETAG"))) > 0)
		return ret;

	metadata->status = OCI_GetInt2(session->oracle_result, "STATUS");
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata status: %l", metadata->status);

	metadata->length = OCI_GetBigInt2(session->oracle_result, "LENGTH");
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata length: %l", metadata->length);

	metadata->upload_date = OCI_GetInt2(session->oracle_result, "UPLOAD_DATE");
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata upload_date: %l", metadata->upload_date);

	if (session->oracle_statement)
		OCI_StatementFree(session->oracle_statement);
	if (session->oracle_connection)
		OCI_API OCI_ConnectionFree(session->oracle_connection);
#endif

	return NGX_OK;
}

