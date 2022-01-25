/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "filter.h"
#include "fs.h"
#include "index.h"
#include "cache.h"

// We need this here as a declaration only; it is defined in main header file which will resolve it at runtime.
ngx_module_t ngx_http_cdn_module;

/**
 * Polyfill for memstr()
 */
char *memstr(char *haystack, char *needle, int64_t size) {
	char *p;

	for (p = haystack; p <= (haystack - strlen(needle) + size); p++) {
		if (memcmp(p, needle, strlen(needle)) == 0)
			return p;
	}

	return NULL;
}

/**
 * Convert Nginx string to normal using Nginx pool
 */
char *from_ngx_str(ngx_pool_t *pool, ngx_str_t ngx_str) {
	char *ret;

	if (! ngx_str.len)
		return NULL;

	if ((ret = ngx_pcalloc(pool, ngx_str.len + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, pool->log, 0, "Failed to allocate %l bytes in from_ngx_str().", ngx_str.len + 1);
		return NULL;
	}

	memcpy(ret, ngx_str.data, ngx_str.len);
	return ret;
}


/**
 * Convert Nginx string to normal using malloc
 */
char *from_ngx_str_malloc(ngx_pool_t *pool, ngx_str_t ngx_str) {
	char *ret;

	if (! ngx_str.len)
		return NULL;

	if ((ret = calloc(ngx_str.len + 1, 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, pool->log, 0, "Failed to allocate %l bytes in from_ngx_str().", ngx_str.len + 1);
		return NULL;
	}

	memcpy(ret, ngx_str.data, ngx_str.len);
	return ret;
}

/**
 * Encode a string to base16 string
 */
void base16_encode(char *in, char *out) {
	size_t  i;

	if (in == NULL || strlen(in) == 0) {
		out[0] = '\0';
		return;
	}

	for (i=0; i < strlen(in); i++) {
		out[i * 2]   = "0123456789abcdef"[in[i] >> 4];
		out[i * 2 + 1] = "0123456789abcdef"[in[i] & 0x0F];
	}
	out[strlen(in) * 2] = '\0';
}

/**
 * Get stat of a file
 */
ngx_int_t get_stat(metadata_t *metadata, ngx_http_request_t *r) {
	struct stat statbuf;
	int fd;

	// Open file
	if ((fd = open(metadata->path, O_RDONLY)) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s open() error %s", metadata->file16, metadata->path, strerror(errno));
		if (errno == ENOENT)
			return NGX_HTTP_NOT_FOUND;
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	fstat(fd, &statbuf);
	metadata->length = statbuf.st_size;
	metadata->upload_timestamp = statbuf.st_mtime;

	if (close(fd) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s close() error %s", metadata->file16, metadata->path, strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	return NGX_OK;
}


/**
 * Helper: Get the full path from a file name
 */
void get_path0(char *fs_root, int fs_depth, char *filename, char *result) {
	int i, pos=0;

	memcpy(result, fs_root, strlen(fs_root));
	pos += strlen(fs_root);

	memcpy(result + pos, "/", 1);
	pos ++;

	for (i=0; i < fs_depth; i++) {
		memcpy(result + pos, filename + i, 1);
		pos ++;
		memcpy(result + pos, "/", 1);
		pos ++;
	}

	memcpy(result + pos, filename, strlen(filename));
}


/**
 * Get the full path from a file name
 */
ngx_int_t get_path(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	int len;

	len = strlen(session->instance->fs->root) + 1 + 2 * session->instance->fs->depth + strlen(metadata->file16);
	if ((metadata->path = ngx_pcalloc(r->pool, len + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for path.", len + 1);
		return NGX_ERROR;
	}
	bzero(metadata->path, len + 1);
	get_path0(session->instance->fs->root, session->instance->fs->depth, metadata->file16, metadata->path);

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s using path: %s", metadata->file16, metadata->path);

	return NGX_OK;
}

/**
 * Decide on full path from a file name - for POST
 */
ngx_int_t get_path2(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	char ver_len[12], path[2048], prefix[1536];

	// We have the file hash, but do not know yet which ver to use

	// The path prefix will always be the same, no matter what ver is
	bzero(&prefix[0], 1536);
	get_path0(session->instance->fs->root, session->instance->fs->depth, metadata->hash, &prefix[0]);

	// Try all possible ver up to MAX_VER
	while (metadata->ver < MAX_VER) {
		// Get the length of current ver
		sprintf(&ver_len[0], "%u", metadata->ver);

		// Calculate length of the path and compose it
		sprintf(&path[0], "%s.%u", &prefix[0], metadata->ver);

		// Stat the path: if not exists, break; else, repeat with ver++
		struct stat statbuf;
		if ((stat(&path[0], &statbuf)) < 0) {
			if (errno == ENOENT)
				break;
			else
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s stat returned error for path %s: %s", metadata->hash, &path[0], strerror(errno));
		}

		metadata->ver ++;
	}

	errno = 0;

	// If version too big, bail out
	if (metadata->ver == MAX_VER) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s too many versions found on disk: %l", metadata->hash, metadata->ver);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Save path
	if ((metadata->path = ngx_pcalloc(r->pool, strlen(&path[0]) + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for path.", strlen(&path[0]) +1);
		return NGX_ERROR;
	}
	strcpy(metadata->path, &path[0]);

	// Save file
	sprintf(&ver_len[0], "%u", metadata->ver);
	if ((metadata->file16 = ngx_pcalloc(r->pool, strlen(metadata->hash) + 1 + strlen(&ver_len[0]) + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for file.", strlen(metadata->hash) + 1 + strlen(&ver_len[0]) + 1);
		return NGX_ERROR;
	}
	sprintf(metadata->file16, "%s.%u", metadata->hash, metadata->ver);

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s using path: %s", metadata->file16, metadata->path);

	return NGX_OK;
}

/**
 * Set metadata field from char value
 */
ngx_int_t set_metadata_field (ngx_http_request_t *r, char **field, char *field_name, const char *value) {
	char *f;

	if (value) {
		if ((f = ngx_pcalloc(r->pool, strlen(value) + 1)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata %s.", field_name, strlen(value) + 1);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		strcpy(f, value);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata %s: %s", field_name, f);
	}
	else {
		if ((f = ngx_pcalloc(r->pool, 1)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata %s.", field_name, 1);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		sprintf(f, "%s", "");
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found metadata %s: empty value", field_name);
	}

	*field = f;

	return NGX_OK;
}

/**
 * Store a header
 */
static inline ngx_int_t store_header(session_t *session, ngx_http_request_t *r, ngx_str_t name, ngx_str_t value) {
	cdn_kvp_t *headers;

	// NB: Nginx pool does not have realloc, so we need to emulate it
	//TODO: Maybe allocate bigger blocks to avoid doing a realloc on each new header?

	// Always allocate memory
	headers = ngx_pnalloc(r->pool, sizeof(cdn_kvp_t) * (session->headers_count + 1));
	if (headers == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for %l headers KVP.", sizeof(cdn_kvp_t) * (session->headers_count + 1), session->headers_count + 1);
		return NGX_ERROR;
	}

	// If we have previous values, copy them
	if (session->headers_count)
		memcpy(headers, session->headers, sizeof(cdn_kvp_t) * session->headers_count);
	session->headers = headers;

	// Extract header name
	session->headers[session->headers_count].name = from_ngx_str(r->pool, name);

	// Extract header value
	session->headers[session->headers_count].value = from_ngx_str(r->pool, value);

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found header %s: %s", session->headers[session->headers_count].name, session->headers[session->headers_count].value);

	session->headers_count ++;

	return NGX_OK;
}

/**
 * Extract all headers
 */
ngx_int_t get_all_headers(session_t *session, ngx_http_request_t *r) {
	int i, j;
	ngx_table_elt_t *h;
	ngx_list_part_t *part;

	part = &r->headers_in.headers.part;
	for (i=0; i < r->headers_in.headers.nalloc; i++) {
		h = part->elts;
		for (j=0; j < part->nelts; j++)
			store_header(session, r, h[j].key, h[j].value);

		part = part->next;
	}

	return NGX_OK;
}

/**
 * Extract all cookies from headers
 */
ngx_int_t get_all_cookies(session_t *session, ngx_http_request_t *r) {
	int i, j, cookie_index = -1;
	char *s0, *s1, *s2;
	char *str1, *str2, *token, *subtoken, *saveptr1, *saveptr2;
	char *cookie_delim = " ", *cookie_subdelim = "=";
	ngx_table_elt_t **elts;
	cdn_kvp_t *cookies;

	if (! r->headers_in.cookies.nelts) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "No cookies found");
		return NGX_OK;
	}

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found a total of %l Cookie header", r->headers_in.cookies.nelts);
	elts = r->headers_in.cookies.elts;
	session->cookies_count = r->headers_in.cookies.nelts;

	// Allocate initial memory we have at least r->headers_in.cookies.nelts, but may be more)
	session->cookies = ngx_pnalloc(r->pool, sizeof(cdn_kvp_t) * r->headers_in.cookies.nelts);
	if (session->cookies == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for %l cookies KVP.", sizeof(cdn_kvp_t) * r->headers_in.cookies.nelts, r->headers_in.cookies.nelts);
		return NGX_ERROR;
	}

	for (i=0; i<r->headers_in.cookies.nelts; i++) {
		s0 = from_ngx_str(r->pool, elts[i]->value);
		for (str1 = s0; ; str1 = NULL) {
			token = strtok_r(str1, cookie_delim, &saveptr1);
			if (token == NULL)
				break;

			s1 = strchr(token, ';');
			if (s1 == token + strlen(token) - 1) {
				s2 = ngx_pcalloc(r->pool, strlen(token));
				if (s2 == NULL) {
					ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for cookie token.", strlen(token));
					return NGX_ERROR;
				}
				strncpy(s2, token, strlen(token) - 1);
			}
			else
				s2 = token;

			// Check to see if we have space to accommodate the cookie
			cookie_index ++;
			if (cookie_index == session->cookies_count) {
				cookies = ngx_pnalloc(r->pool, sizeof(cdn_kvp_t) * (session->cookies_count + 1));
				if (session->cookies == NULL) {
					ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for %l cookies KVP.", sizeof(cdn_kvp_t) * (session->cookies_count + 1), session->cookies_count + 1);
					return NGX_ERROR;
				}
				memcpy(cookies, session->cookies, sizeof(cdn_kvp_t) * session->cookies_count);
				session->cookies = cookies;
			}
			session->cookies_count ++;

			// Extract the cookie
			for (j=0, str2 = s2; ; j++, str2 = NULL) {
				subtoken = strtok_r(str2, cookie_subdelim, &saveptr2);
				if (subtoken == NULL)
					break;

				if (j == 0) {
					session->cookies[cookie_index].name = ngx_pcalloc(r->pool, strlen(subtoken) + 1);
					if (session->cookies[cookie_index].name == NULL) {
						ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for cookie name.", strlen(subtoken) + 1);
						return NGX_ERROR;
					}
					strcpy(session->cookies[cookie_index].name, subtoken);
				}
				else if (j == 1) {
					session->cookies[cookie_index].value = ngx_pcalloc(r->pool, strlen(subtoken) + 1);
					if (session->cookies[cookie_index].value == NULL) {
						ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for cookie value.", strlen(subtoken) + 1);
						return NGX_ERROR;
					}
					strcpy(session->cookies[cookie_index].value, subtoken);
				}
				else
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Malformed cookie %s", s0);
			}

			if (j == 2) {
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found cookie %s with value %s", session->cookies[cookie_index].name, session->cookies[cookie_index].value);
			}
		}
	}

	return NGX_OK;
}

/**
 * Helper: SQL DSN parser
 */
static inline ngx_int_t property_sql(ngx_http_request_t *r, char **field, char *field_name, char *value) {
	char *f;

	if ((f = calloc(strlen(value) + 1, 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for SQL property %s: %s.", strlen(value) + 1, field_name, value);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	strcpy(f, value);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found SQL property %s: %s", field_name, f);
	*field = f;

	return NGX_OK;
}

/**
 * Auth matrix parser
 */
static inline auth_matrix_t *init_auth_matrix(ngx_http_request_t *r, char *matrix_str) {
	auth_matrix_t *matrix;

	if ((matrix = malloc(sizeof(auth_matrix_t))) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for auth matrix.", sizeof(auth_matrix_t));
		return NULL;
	}

	matrix->auth_resp = (! strcmp(filter_token(r, matrix_str, ":", 1), DEFAULT_MATRIX_ALLOW)) ? MATRIX_ALLOW_STATUS : MATRIX_DENY_STATUS;
	matrix->auth_noresp = (! strcmp(filter_token(r, matrix_str, ":", 2), DEFAULT_MATRIX_ALLOW)) ? MATRIX_ALLOW_STATUS : MATRIX_DENY_STATUS;
	matrix->noauth_resp = (! strcmp(filter_token(r, matrix_str, ":", 3), DEFAULT_MATRIX_ALLOW)) ? MATRIX_ALLOW_STATUS : MATRIX_DENY_STATUS;
	matrix->noauth_noresp = (! strcmp(filter_token(r, matrix_str, ":", 4), DEFAULT_MATRIX_ALLOW)) ? MATRIX_ALLOW_STATUS : MATRIX_DENY_STATUS;

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Matrix: setting auth_resp=%l", matrix->auth_resp);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Matrix: setting auth_noresp=%l", matrix->auth_noresp);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Matrix: setting noauth_resp=%l", matrix->noauth_resp);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Matrix: setting noauth_noresp=%l", matrix->noauth_noresp);

	return matrix;
}

/**
 * Init instance
 */
instance_t *instance_init(ngx_http_request_t *r) {
	instance_t *instance, *instance_tmp;
	ngx_http_cdn_loc_conf_t *cdn_loc_conf;
	char *matrix_str, *jwt_key, *db_dsn, *str, *token, *saveptr;
	int fd, i, ret, cache_size;
	struct stat statbuf;
	time_t t = time(NULL);
	struct tm lt = {0};

	// Get config
	cdn_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_cdn_module);

	// Create a new instance in the global array
	pthread_mutex_lock(&globals->lock);
	if ((instance_tmp = realloc(globals->instances, (globals->instances_cnt + 1) * sizeof(instance_t))) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to realloc global instances");
		pthread_mutex_unlock(&globals->lock);
		return NULL;
	}
	globals->instances = instance_tmp;
	instance = &globals->instances[globals->instances_cnt];
	globals->instances_cnt ++;
	pthread_mutex_unlock(&globals->lock);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Created global space for new instance, count is now %l", globals->instances_cnt);

	instance->id = cdn_loc_conf->instance_id;
	instance->jwt_key = NULL;
	instance->dsn = NULL;
	instance->matrix_dnld = NULL;
	instance->matrix_del = NULL;
	instance->matrix_upld = NULL;

	// Init FS
	if ((instance->fs = fs_init()) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to init FS");
		return NULL;
	}
	instance->fs->root = from_ngx_str_malloc(r->pool, cdn_loc_conf->fs_root);
	instance->fs->depth = atoi(from_ngx_str(r->pool, cdn_loc_conf->fs_depth));
	instance->fs->server_id = atoi(from_ngx_str(r->pool, cdn_loc_conf->server_id));

	// Init index
	if ((instance->index = index_init()) == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to init index");
		return NULL;
	}
	instance->index->prefix = from_ngx_str_malloc(r->pool, cdn_loc_conf->index_prefix);

	// Init cache for internal transport (if enabled in config)
	if ((cache_size = atoi(from_ngx_str(r->pool, cdn_loc_conf->cache_size))) > 0) {
		if ((instance->cache = cache_init()) == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to init in-memory cache (malloc failed)");
			return NULL;
		}
		instance->cache->mem_max = CACHE_SIZE_MULTIPLIER * cache_size;
	}
	else
		instance->cache = NULL;

	// Init authorisation matrices
	matrix_str = from_ngx_str(r->pool, cdn_loc_conf->matrix_dnld);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing matrix: matrix_dnld: %s", matrix_str);
	if ((instance->matrix_dnld = init_auth_matrix(r, matrix_str)) == NULL)
		return NULL;

	matrix_str = from_ngx_str(r->pool, cdn_loc_conf->matrix_upld);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing matrix: matrix_upld: %s", matrix_str);
	if ((instance->matrix_upld = init_auth_matrix(r, matrix_str)) == NULL)
		return NULL;

	matrix_str = from_ngx_str(r->pool, cdn_loc_conf->matrix_del);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing matrix: matrix_del: %s", matrix_str);
	if ((instance->matrix_del = init_auth_matrix(r, matrix_str)) == NULL)
		return NULL;

	// Init JWT
	jwt_key = from_ngx_str_malloc(r->pool, cdn_loc_conf->jwt_key);
	if (strstr(jwt_key, "/") == jwt_key) {
		if ((fd = open(jwt_key, O_RDONLY)) < 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to open JWT key file %s: %s", jwt_key, strerror(errno));
			return NULL;
		}

		fstat(fd, &statbuf);

		if ((instance->jwt_key = malloc(statbuf.st_size + 1)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for jwt_key", statbuf.st_size + 1);
			return NULL;
		}

		if (read(fd, instance->jwt_key, statbuf.st_size) < statbuf.st_size) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to read %l bytes from JWT key file %s: %s", statbuf.st_size, jwt_key, strerror(errno));
			return NULL;
		}

		if (close(fd) < 0)
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to close JWT key file %s: %s", jwt_key, strerror(errno));

		instance->jwt_key[statbuf.st_size] = '\0';
	}
	else {
		// Copy the string from config
		if ((instance->jwt_key = strdup(jwt_key)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for jwt_key", statbuf.st_size + 1);
			return NULL;
		}
	}

	// Init DSN (only for Redis, Oracle and MySQL transport)
	if (cdn_loc_conf->db_dsn.len > 4) {
		if ((instance->dsn = malloc(sizeof(dsn_t))) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for dsn", sizeof(dsn_t));
			return NULL;
		}

		instance->dsn->dsn = from_ngx_str_malloc(r->pool, cdn_loc_conf->db_dsn);
		instance->dsn->host = NULL;
		instance->dsn->port_str = NULL;
		instance->dsn->port = 0;
		instance->dsn->socket = NULL;
		instance->dsn->user = NULL;
		instance->dsn->password = NULL;
		instance->dsn->db = NULL;

		// host:port|socket:user:password:db
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing DSN: %s", instance->dsn->dsn);
		db_dsn = strdup(instance->dsn->dsn);
		for (str = db_dsn, i = 0; ; str = NULL, i++) {
			token = strtok_r(str, ":", &saveptr);
			if (token == NULL)
				break;

			switch(i) {
				case 0:
					if ((ret = property_sql(r, &instance->dsn->host, "host", token)) > 0)
						return NULL;
					break;
				case 1:
					if ((ret = property_sql(r, &instance->dsn->port_str, "port_str", token)) > 0)
						return NULL;
					break;
				case 2:
					if ((ret = property_sql(r, &instance->dsn->user, "user", token)) > 0)
						return NULL;
					break;
				case 3:
					if ((ret = property_sql(r, &instance->dsn->password, "password", token)) > 0)
						return NULL;
					break;
				case 4:
					if ((ret = property_sql(r, &instance->dsn->db, "db", token)) > 0)
						return NULL;
					break;
			}
		}
		free(db_dsn);

		// Detect if we were given a port or a socket
		instance->dsn->port = atoi(instance->dsn->port_str);

		if (instance->dsn->port == 0)
			instance->dsn->socket = instance->dsn->port_str;
	}

	// Init time offset
	// NB: This effectively requires restart when DST goes on/off
	localtime_r(&t, &lt);
	instance->tm_gmtoff = lt.tm_gmtoff;

	return instance;
}

/**
 * Get instance
 */
instance_t *instance_get(ngx_http_request_t *r, int instance_id) {
	int i;

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Instance count is %l", globals->instances_cnt);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Searching for instance with ID %uD", instance_id);

	for (i=0; i < globals->instances_cnt; i++) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Checking existing instance in slot %l with ID %uD", i, globals->instances[i].id);
		if (instance_id == globals->instances[i].id)
			return &globals->instances[i];
	}

	return NULL;
}

/**
 * Init session
 */
session_t *init_session(ngx_http_request_t *r) {
	ngx_http_cdn_loc_conf_t *cdn_loc_conf;
	session_t *session;

	// Init session
	if ((session = ngx_pcalloc(r->pool, sizeof(session_t))) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for session.", sizeof(session_t));
		return NULL;
	}

	// Get config
	cdn_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_cdn_module);

	// Check if we have the instance saved and retrieve it
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Looking for instance ID %uD", cdn_loc_conf->instance_id);
	session->instance = instance_get(r, cdn_loc_conf->instance_id);
	if (session->instance) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found instance ID %uD", session->instance->id);
	}
	else {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Instance ID %uD not found, creating new", cdn_loc_conf->instance_id);
		if ((session->instance = instance_init(r)) == NULL)
			return NULL;
	}

	// Set options for OPTIONS
	if (r->method & (NGX_HTTP_OPTIONS)) {
		session->cors_origin = from_ngx_str(r->pool, cdn_loc_conf->cors_origin);
		return session;
	}

	// Set common options (for GET|HEAD|DELETE, POST and PUT)
	session->request_type = from_ngx_str(r->pool, cdn_loc_conf->request_type);
	session->transport_type = from_ngx_str(r->pool, cdn_loc_conf->transport_type);
	session->auth_cookie = from_ngx_str(r->pool, cdn_loc_conf->auth_cookie);
	session->auth_header = from_ngx_str(r->pool, cdn_loc_conf->auth_header);
	session->auth_type = from_ngx_str(r->pool, cdn_loc_conf->auth_type);
	session->auth_token = NULL;
	session->auth_value = NULL;
	session->auth_filter = from_ngx_str(r->pool, cdn_loc_conf->auth_filter);
	session->db_dsn = from_ngx_str(r->pool, cdn_loc_conf->db_dsn);
	session->unix_socket = from_ngx_str(r->pool, cdn_loc_conf->unix_socket);
	session->tcp_host = from_ngx_str(r->pool, cdn_loc_conf->tcp_host);
	session->tcp_port = atoi(from_ngx_str(r->pool, cdn_loc_conf->tcp_port));
	session->http_url = from_ngx_str(r->pool, cdn_loc_conf->http_url);
	session->auth_request = NULL;
	session->auth_response = NULL;
	session->auth_response_count = 0;
	session->curl = NULL;
	session->jwt_field = from_ngx_str(r->pool, cdn_loc_conf->jwt_field);
	session->jwt_json = NULL;
	session->http_method = ngx_pcalloc(r->pool, 8);
	session->read_only = from_ngx_str(r->pool, cdn_loc_conf->read_only);

#ifdef CDN_ENABLE_MONGO
	session->mongo_db = from_ngx_str(r->pool, cdn_loc_conf->mongo_db);
	session->mongo_collection = from_ngx_str(r->pool, cdn_loc_conf->mongo_collection);
	session->mongo_filter = from_ngx_str(r->pool, cdn_loc_conf->mongo_filter);
#endif

	// Set options for GET, HEAD and DELETE
	if (r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD | NGX_HTTP_DELETE)) {
		session->all_headers = from_ngx_str(r->pool, cdn_loc_conf->all_headers);
		session->all_cookies = from_ngx_str(r->pool, cdn_loc_conf->all_cookies);
		session->headers = NULL;
		session->headers_count = 0;
		session->cookies = NULL;
		session->cookies_count = 0;
		session->hdr_if_none_match = NULL;
		session->hdr_if_modified_since = -1;
		session->hdr_range = NULL;
		session->hdr_ranges = NULL;
		session->hdr_ranges_cnt = 0;
		session->hdr_if_range_etag = NULL;
		session->hdr_if_range_time = -1;

		// Method-specific init
		if (r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)) {
			sprintf(session->http_method, "GET");
			session->sql_query = from_ngx_str(r->pool, cdn_loc_conf->sql_select);
		}
		else if (r->method & (NGX_HTTP_DELETE)) {
			sprintf(session->http_method, "DELETE");
			session->sql_query = from_ngx_str(r->pool, cdn_loc_conf->sql_select);
			session->sql_query2 = from_ngx_str(r->pool, cdn_loc_conf->sql_delete);
		}
	}
	else if (r->method & (NGX_HTTP_POST)) {
		sprintf(session->http_method, "POST");
		session->sql_query = from_ngx_str(r->pool, cdn_loc_conf->sql_insert);
	}
	else if (r->method & (NGX_HTTP_PUT)) {
		sprintf(session->http_method, "PUT");
		session->sql_query = from_ngx_str(r->pool, cdn_loc_conf->sql_insert);
	}

	return session;
}

/**
 * Init metadata
 */
metadata_t *init_metadata(ngx_http_request_t *r) {
	metadata_t *metadata;

	// Init file metadata
	if ((metadata = ngx_pcalloc(r->pool, sizeof(metadata_t))) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for metadata.", sizeof(metadata_t));
		return NULL;
	}

	metadata->hash = NULL;
	metadata->ver = 0;
	metadata->ext = NULL;
	metadata->ext16 = NULL;
	metadata->pack = NULL;
	metadata->file = NULL;
	metadata->file16 = NULL;
	metadata->filename = NULL;
	metadata->path = NULL;
	metadata->content_type = NULL;
	metadata->content_disposition = NULL;
	metadata->etag = NULL;
	metadata->data = NULL;
	metadata->length = -1;
	metadata->upload_timestamp = -1;
	metadata->status = -1;
	metadata->auth_value = NULL;

	return metadata;
}

/**
 * Extract authentication token
 */
ngx_int_t get_auth_token(session_t *session, ngx_http_request_t *r) {
	char *hdr_authorization;
	bool match = false;
	int i, j;
	ngx_int_t ret;
	ngx_str_t cookie_name, cookie_value;
	ngx_table_elt_t *h;
	ngx_list_part_t *part;

	// First, check Authorization header
	if (r->headers_in.authorization) {
		hdr_authorization = from_ngx_str(r->pool, r->headers_in.authorization->value);

		if (strstr(hdr_authorization, "Bearer")) {
			if ((session->auth_token = ngx_pcalloc(r->pool, strlen(hdr_authorization) + 1)) == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for Authorization header.", strlen(hdr_authorization) + 1);
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}

			strncpy(session->auth_token, hdr_authorization + 7, strlen(hdr_authorization) - 7);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Auth token found in Authorization header: %s", session->auth_token);
		}
	}

	// Next try a custom header, if defined
	if (strcmp(session->auth_header, DEFAULT_AUTH_HEADER)) {
		part = &r->headers_in.headers.part;
		for (i=0; i < r->headers_in.headers.nalloc; i++) {
			h = part->elts;
			for (j=0; j < part->nelts; j++) {
				if (! ngx_strncasecmp( h[j].key.data, (u_char *) session->auth_header, h[j].key.len)) {
					session->auth_token = from_ngx_str(r->pool, h[j].value);
					match = true;
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Auth token found in header %s: %s", session->auth_header, session->auth_token);
					break;
				}
			}

			if (match)
				break;

			if (part->next)
				part = part->next;
			else
				break;
		}
	}

	// If cookie name given in config, try to find the cookie and to extract auth token from it
	if (strcmp(session->auth_cookie, DEFAULT_AUTH_COOKIE)) {
		cookie_name.len = strlen(session->auth_cookie);
		cookie_name.data = (u_char *) session->auth_cookie;

		ret = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &cookie_name, &cookie_value);
		if (ret == NGX_DECLINED) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Cookie %s for auth token not found", session->auth_cookie);
		}
		else {
			session->auth_token = from_ngx_str(r->pool, cookie_value);
		}
	}

	return NGX_OK;
}

/**
 * Extract URI
 */
ngx_int_t get_uri(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	char *uri, *s0, *s1, *s2, *saveptr1, *p1, *p2;
	int len;

	// URI
	uri = from_ngx_str(r->pool, r->uri);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found URI: %s", uri);

	// Extract file ID
	// URL format: http://cdn.example.com/some-file-id
	s0 = from_ngx_str(r->pool, r->uri);
	s1 = strtok_r(s0, "/", &saveptr1);
	if (s1 == NULL)
		return NGX_HTTP_BAD_REQUEST;

	s2 = s1;

	while ((s1 = strtok_r(NULL, "/", &saveptr1)))
		s2 = s1;

	if ((metadata->file = ngx_pcalloc(r->pool, strlen(s2) + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for URI pasring.", strlen(s2) + 1);
		return NGX_ERROR;
	}
	strcpy(metadata->file, s2);

	// If the file ID has an extension, get it and set properly the file16 field
	if ((p1 = strstr(metadata->file, "."))) {
		if ((p2 = strstr(p1 + 1, "."))) {
			len = strlen(p2) - 1;

			// Get ext
			if ((metadata->ext = ngx_pcalloc(r->pool, len + 1)) == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for ext.", len + 1);
				return NGX_ERROR;
			}
			strcpy(metadata->ext, p2 + 1);

			// Convert to ext16
			if ((metadata->ext16 = ngx_pcalloc(r->pool, 2 * len + 1)) == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for ext16.", len + 1);
				return NGX_ERROR;
			}
			base16_encode(metadata->ext, metadata->ext16);

			// Create file16
			len = strlen(metadata->file) - strlen(p2 + 1) + strlen(metadata->ext16);
			if ((metadata->file16 = ngx_pcalloc(r->pool, len + 1)) == NULL) {
				ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for file16.", len + 1);
				return NGX_ERROR;
			}
			memset(metadata->file16 + len, '\0', 1);
			len = strlen(metadata->file) - strlen(p2 + 1);
			memcpy(metadata->file16, metadata->file, len);
			memcpy(metadata->file16 + len, metadata->ext16, strlen(metadata->ext16));
		}
		else
			metadata->file16 = metadata->file;
	}
	else
		metadata->file16 = metadata->file;

	return NGX_OK;
}


/**
 * Perform authorisation check
 */
void auth_check(session_t *session, metadata_t *metadata, ngx_http_request_t *r) {
	// Skip if status is already set
	if (metadata->status > 0)
		return;

	// If auth_value was provided and does not match the response, reset response count
	if (session->auth_value && metadata->auth_value) {
		if (strcmp (session->auth_value, metadata->auth_value)) {
			session->auth_response_count = 0;
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Auth check: mismatch on auth_value, resetting response count.");
		}
	}
}

/**
 * Trim a string and get it back as a 64-bit signed int (-1 for empty strings, -2 for malloc error)
 */
int64_t get_trimmed_int(char *in) {
	char *s1, *s2;
	long ret = -1;

	if ((s1 = strdup(in)) == NULL)
		return -2;
	s2 = s1;

	// Kill any trailing space (replace with NULL)
	while ( *(s1 + strlen(s1) -1) == 32)
		memset(s1 + strlen(s1) - 1, '\0', 1);

	// Kill any leading space (shift forward a copy of the pointer)
	while ( *(s2) == 32 )
		s2++;

	// Use default -1 for empty values
	if (strlen(s2))
		ret = atol(s2);

	free(s1);

	return ret;
}


/**
 * Extract header etag
 */
char *trim_quotes(ngx_http_request_t *r, char *s) {
	char *ret, *s1, *s2;

	s1 = strchr(s, '"');
	s2 = strrchr(s, '"');
	if ((s1 == s) && (s2 == s + strlen(s) - 1)) {
		if ((ret = ngx_pcalloc(r->pool, strlen(s) - 1)) == NULL)
			return NULL;

		strncpy(ret, s + 1, strlen(s) - 2);
	}
	else
		ret = s;

	return ret;
}

