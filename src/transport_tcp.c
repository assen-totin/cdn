#include "common.h"

/**
 * Get file metadata over TCP socket
 */
ngx_int_t transport_tcp(session_t *session, ngx_http_request_t *r) {
	// Socket variables
	struct sockaddr_in remote_in;
	struct hostent *host;
	int tcp_socket, bytes_in, tcp_response_len, tcp_response_pos;
	char msg_in[TCP_BUFFER_CHUNK];

	// Init the TCP socket
	if ((tcp_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to create socket: %s", strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Resolve host
	if ((host = gethostbyname(session->tcp_host)) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to resolve host address %s: %s", session->tcp_host, strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Zero the structure, set socket type, port and address
	memset(&remote_in, '\0', sizeof(struct sockaddr_in));
	remote_in.sin_family = AF_INET;
	remote_in.sin_port = htons(session->tcp_port);
	remote_in.sin_addr = *((struct in_addr *) host->h_addr);

	// Connect to the authorisation service
	if (connect(tcp_socket, (struct sockaddr *)&remote_in, sizeof(remote_in)) == -1) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to connect to TCP socket %s:%l %s", session->tcp_host, session->tcp_socket, strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Send the message over the socket
	if (send(tcp_socket, session->auth_request, strlen(session->auth_request), 0) == -1) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to write to TCP socket %s: %s", session->tcp_socket, strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Signal we are done
	shutdown(tcp_socket, SHUT_WR);

	// Await reponse
	tcp_response_pos = 0;
	session->auth_response = malloc(TCP_BUFFER_CHUNK);
	if (session->auth_response == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for auth_response.", TCP_BUFFER_CHUNK);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	tcp_response_len = TCP_BUFFER_CHUNK;
	memset(session->auth_response, '\0', tcp_response_len);

	memset(&msg_in[0], '\0', sizeof(msg_in));

	while(1) {
		// Blocking read till we get a response
		if ((bytes_in = read(tcp_socket, &msg_in[0], sizeof(msg_in)-1)) == -1) {
			free(session->auth_response);
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to read from TCP socket %s: %s", session->tcp_socket, strerror(errno));
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		else {
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Received %u bytes over TCP socket\n", bytes_in);
			if (bytes_in) {
				// We read some more data, append it  (but expand buffer before that if necessary)
				if (tcp_response_pos + bytes_in > tcp_response_len - 1) {
					session->auth_response = realloc(session->auth_response, tcp_response_len + TCP_BUFFER_CHUNK);
					if (session->auth_response == NULL) {
						ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to reallocate %l bytes for auth_response.", tcp_response_len + TCP_BUFFER_CHUNK);
						return NGX_HTTP_INTERNAL_SERVER_ERROR;
					}
				}

				memcpy(session->auth_response + tcp_response_pos, &msg_in[0], bytes_in);
				tcp_response_pos += bytes_in;
			}
			else {
				// NULL_terminate the incoming buffer and exit the loop
				memset(session->auth_response + tcp_response_pos, '\0', 1);
				break;
			}
		}
	}

	// Clean up, log, return
	close(tcp_socket);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Auth server response: %s", session->auth_response);

	return NGX_OK;
}

