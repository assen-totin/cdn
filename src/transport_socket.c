/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"

/**
 * Get file metadata over streaming (Unix or TCP) socket
 */
ngx_int_t transport_socket(session_t *session, ngx_http_request_t *r, int socket_type) {
	// Socket variables
	struct sockaddr_un remote_un;
	struct sockaddr_in remote_in;
	struct hostent *host;
	int sock, addr_len_un, bytes_in, auth_response_len=0, auth_response_pos=0;
	char msg_in[SOCKET_BUFFER_CHUNK], *tmp;

	// Init socket
	if (socket_type == SOCKET_TYPE_UNUX) {
		// Init the Unix socket
		if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to create Unix socket: %s", strerror(errno));
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		// Zero the structure, set socket type and path
		memset(&remote_un, '\0', sizeof(struct sockaddr_un));
		remote_un.sun_family = AF_UNIX;						
		strcpy(remote_un.sun_path, session->unix_socket);
		addr_len_un = strlen(remote_un.sun_path) + sizeof(remote_un.sun_family);

		// Connect to the authorisation service
		if (connect(sock, (struct sockaddr *)&remote_un, addr_len_un) == -1) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to connect to Unix socket %s: %s", session->unix_socket, strerror(errno));
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
	}
	else if (socket_type == SOCKET_TYPE_TCP) {
		// Init the TCP socket
		if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to create TCP socket: %s", strerror(errno));
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
		if (connect(sock, (struct sockaddr *)&remote_in, sizeof(remote_in)) == -1) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to connect to TCP socket %s:%l %s", session->tcp_host, session->tcp_port, strerror(errno));
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
	}
	else {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unknown socket type: %l", socket_type);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Send the message over the socket
	if (send(sock, session->auth_request, strlen(session->auth_request), 0) == -1) {
		if (socket_type == SOCKET_TYPE_UNUX) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to write to Unix socket %s: %s", session->unix_socket, strerror(errno));
		}
		else if (socket_type == SOCKET_TYPE_TCP) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to write to TCP socket %s:%l : %s", session->tcp_host, session->tcp_port,  strerror(errno));
		}
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Signal we are done
	shutdown(sock, SHUT_WR);

	// Await reponse
	while(1) {
		memset(&msg_in[0], '\0', sizeof(msg_in));

		// Blocking read till we get a response
		if ((bytes_in = read(sock, &msg_in[0], sizeof(msg_in)-1)) == -1) {
			free(session->auth_response);

			if (socket_type == SOCKET_TYPE_UNUX) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to read from Unix socket %s: %s", session->unix_socket, strerror(errno));
			}
			else if (socket_type == SOCKET_TYPE_TCP) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to read from TCP socket %s:%l : %s", session->tcp_host, session->tcp_port,  strerror(errno));
			}

			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		else {
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Received %u bytes from socket\n", bytes_in);
			if (bytes_in) {
				// We read some more data, append it (but init or expand buffer before that if necessary)
				if (! session->auth_response) {
					if ((session->auth_response = malloc(SOCKET_BUFFER_CHUNK)) == NULL) {
						ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for auth_response.", SOCKET_BUFFER_CHUNK);
						return NGX_HTTP_INTERNAL_SERVER_ERROR;
					}
					memset(session->auth_response, '\0', SOCKET_BUFFER_CHUNK);
					auth_response_len = SOCKET_BUFFER_CHUNK;
				}

				if (auth_response_pos + bytes_in > auth_response_len - 1) {
					if ((tmp = realloc(session->auth_response, auth_response_len + SOCKET_BUFFER_CHUNK)) == NULL) {
						ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to reallocate %l bytes for auth_response.", auth_response_len + SOCKET_BUFFER_CHUNK);
						return NGX_HTTP_INTERNAL_SERVER_ERROR;
					}
					session->auth_response = tmp;
					auth_response_len += SOCKET_BUFFER_CHUNK;
				}

				memcpy(session->auth_response + auth_response_pos, &msg_in[0], bytes_in);
				auth_response_pos += bytes_in;
			}
			else {
				// NULL_terminate the incoming buffer and exit the loop (if we read any data)
				if (session->auth_response) {
					memset(session->auth_response + auth_response_pos, '\0', 1);
					break;
				}
			}
		}
	}

	// Clean up, log, return
	close(sock);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Auth server response: %s", session->auth_response);

	return NGX_OK;
}

