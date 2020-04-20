#include "common.h"

/**
 * Get file metadata over Unix socket
 */
ngx_int_t transport_unix(session_t *session, ngx_http_request_t *r) {
	// Socket variables
	struct sockaddr_un remote_un;
	int unix_socket, addr_len_un, bytes_in, unix_response_len, unix_response_pos;
	char msg_in[UNIX_BUFFER_CHUNK];

	// Init the Unix socket
	if ((unix_socket = socket(AF_UNIX, UNIX_SOCKET_TYPE, 0)) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to create socket: %s", strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Zero the structure, set socket type and path
	memset(&remote_un, '\0', sizeof(struct sockaddr_un));
	remote_un.sun_family = AF_UNIX;						
	strcpy(remote_un.sun_path, session->unix_socket);
	addr_len_un = strlen(remote_un.sun_path) + sizeof(remote_un.sun_family);

	// Connect to the authorisation service
	if (connect(unix_socket, (struct sockaddr *)&remote_un, addr_len_un) == -1) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to connect to Unix socket %s: %s", session->unix_socket, strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Send the message over the socket
	if (send(unix_socket, session->unix_request, strlen(session->unix_request), 0) == -1) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to write to Unix socket %s: %s", session->unix_socket, strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Signal we are done
	shutdown(unix_socket, SHUT_WR);

	// Await reponse
	unix_response_pos = 0;
	session->unix_response = malloc(UNIX_BUFFER_CHUNK);
	if (session->unix_response == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for unix_response.", UNIX_BUFFER_CHUNK);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	unix_response_len = UNIX_BUFFER_CHUNK;
	memset(session->unix_response, '\0', unix_response_len);

	memset(&msg_in[0], '\0', sizeof(msg_in));

	while(1) {
		// Blocking read till we get a response
		if ((bytes_in = read(unix_socket, &msg_in[0], sizeof(msg_in)-1)) == -1) {
			free(session->unix_response);
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to read from Unix socket %s: %s", session->unix_socket, strerror(errno));
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		else {
			printf("Received %u bytes over Unix socket\n", bytes_in);
			if (bytes_in) {
				// We read some more data, append it  (but expand buffer before that if necessary)
				if (unix_response_pos + bytes_in > unix_response_len - 1) {
					session->unix_response = realloc(session->unix_response, unix_response_len + UNIX_BUFFER_CHUNK);
					if (session->unix_response == NULL) {
						ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to reallocate %l bytes for unix_response.", unix_response_len + UNIX_BUFFER_CHUNK);
						return NGX_HTTP_INTERNAL_SERVER_ERROR;
					}
				}

				memcpy(session->unix_response + unix_response_pos, &msg_in[0], bytes_in);
				unix_response_pos += bytes_in;
			}
			else {
				// NULL_terminate the incoming buffer and exit the loop
				memset(session->unix_response + unix_response_pos, '\0', 1);
				break;
			}
		}
	}

	// Clean up, log, return
	close(unix_socket);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Auth server response: %s", session->unix_response);

	return NGX_OK;
}

