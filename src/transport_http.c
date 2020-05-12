/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"

/**
 * Callback to append data as received by cURL
 */
static uint http_cb(char *msg_in, uint size, uint bytes_in, session_t *session) {
	char *tmp;

	if (session->auth_response_pos + bytes_in > session->auth_response_len - 1) {
		if ((tmp = realloc(session->auth_response, session->auth_response_len + SOCKET_BUFFER_CHUNK)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, session->r->connection->log, 0, "Failed to reallocate %l bytes for auth_response.", session->auth_response_len + SOCKET_BUFFER_CHUNK);
			return 0;
		}
		session->auth_response = tmp;
		session->auth_response_len += SOCKET_BUFFER_CHUNK;
	}

	memcpy(session->auth_response + session->auth_response_pos, msg_in, bytes_in);
	session->auth_response_pos += bytes_in;
	session->auth_response[session->auth_response_pos + 1] = '\0';

	return bytes_in;
}

/**
 * Get file metadata over HTTP POST
 */
ngx_int_t transport_http(session_t *session, ngx_http_request_t *r) {
	CURLcode res;

	if ((session->curl = curl_easy_init()) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to init curl: %s", strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Set URL
	curl_easy_setopt(session->curl, CURLOPT_URL, session->http_url);

	// Follow redirects, if any
	curl_easy_setopt(session->curl, CURLOPT_FOLLOWLOCATION, 1L);

	// Set response callback; attach request pointer to session so that we may use the logger in the callback;
	session->r = r;
	curl_easy_setopt(session->curl, CURLOPT_WRITEFUNCTION, http_cb);
	curl_easy_setopt(session->curl, CURLOPT_WRITEDATA, session);

	//Set POST payload
	curl_easy_setopt(session->curl, CURLOPT_POSTFIELDS, session->auth_request);

	// Prepare some buffer for response
	if ((session->auth_response = malloc(SOCKET_BUFFER_CHUNK)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for auth_response.", SOCKET_BUFFER_CHUNK);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	session->auth_response_len = SOCKET_BUFFER_CHUNK;
	session->auth_response_pos = 0;

	// Send request
	res = curl_easy_perform(session->curl);
	if(res != CURLE_OK) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to make HTTP request to URL %s: %s", session->http_url, curl_easy_strerror(res));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Auth server response: %s", session->auth_response);

	return NGX_OK;
}

