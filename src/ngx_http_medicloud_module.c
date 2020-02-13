/**
 * Nginx media serving module for Medicloud.
 *
 * @author: Assen Totin assen.totin@curaden.ch
 */

#include "ngx_http_medicloud_module.h"

/**
 * On module init
 */
static ngx_int_t ngx_http_medicloud_module_start(ngx_cycle_t *cycle) {
	mongoc_init();
	return NGX_OK;
}

/**
 * On master process end
 */
static void ngx_http_medicloud_master_end(ngx_cycle_t *cycle) {
	mongoc_cleanup();
}

/**
 * Create location configuration
 */
static void* ngx_http_medicloud_create_loc_conf(ngx_conf_t* cf) {
	ngx_http_medicloud_loc_conf_t* loc_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_medicloud_loc_conf_t));
	if (loc_conf == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Failed to allocate memory for Medicloud location config.");
		return NGX_CONF_ERROR;
	}

	return loc_conf;
}

/**
 * Merge location configuration
 */
static char* ngx_http_medicloud_merge_loc_conf(ngx_conf_t* cf, void* void_parent, void* void_child) {
	ngx_http_medicloud_loc_conf_t *parent = void_parent;
	ngx_http_medicloud_loc_conf_t *child = void_child;

	ngx_conf_merge_str_value(child->jwt_key, parent->jwt_key, "");
	ngx_conf_merge_off_value(child->mongo_enabled, parent->mongo_enabled, MONGO_DEFAULT_ENABLED);
	ngx_conf_merge_str_value(child->mongo_url, parent->mongo_url, MONGO_DEFAULT_URL);
	ngx_conf_merge_str_value(child->mongo_db, parent->mongo_db, MONGO_DEFAULT_DB);
	ngx_conf_merge_off_value(child->fs_enabled, parent->fs_enabled, FS_DEFAULT_ENABLED);
	ngx_conf_merge_str_value(child->fs_root, parent->fs_root, FS_DEFAULT_ROOT);
	ngx_conf_merge_uint_value(child->fs_depth, parent->fs_depth, FS_DEFAULT_DEPTH);

	return NGX_CONF_OK;
}

/**
 * Init module and set handler
 */
static char *ngx_http_medicloud_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_medicloud_handler;

    return NGX_CONF_OK;
}

/**
 * Content handler
 */
static ngx_int_t ngx_http_medicloud_handler(ngx_http_request_t *r) {
	char *bson_tmp, *bucket, *attachment, *id;
	ngx_http_medicloud_loc_conf_t *medicloud_loc_conf;
	ngx_int_t ret;
	medicloud_grid_file_t grid_file;
	medicloud_mongo_t mongo;
	medicloud_mongo_file_t mongo_file;

	medicloud_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_medicloud_module);

	// Check if we have any backend enabled; return 404 if we have nowhere to read the file from
	if (! medicloud_loc_conf->mongo_enabled && ! medicloud_loc_conf->fs_enabled)
		return NGX_HTTP_NOT_FOUND;

	// Prepare session management data
	sm_t sm;
	sm.uid = NULL;
	sm.token = NULL;
	sm.jwt_key = from_ngx_str(r->pool, medicloud_loc_conf->jwt_key);
	sm.mongo_enabled = medicloud_loc_conf->mongo_enabled;
	sm.mongo_url = from_ngx_str(r->pool, medicloud_loc_conf->mongo_url);
	sm.mongo_db = from_ngx_str(r->pool, medicloud_loc_conf->mongo_db);
	sm.fs_enabled = medicloud_loc_conf->fs_enabled;
	sm.fs_depth = medicloud_loc_conf->fs_depth;
	sm.fs_root = from_ngx_str(r->pool, medicloud_loc_conf->fs_root);

	// URI
	// URI format: /:bucket/download/:id
	// URI format: /:bucket/stream/:id
	sm.uri = from_ngx_str(r->pool, r->uri);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found URI: %s", sm.uri);

	sm.uri_dup = from_ngx_str(r->pool, r->uri);

	// Get bucket
	bucket = strtok(sm.uri_dup, "/");
	sm.bucket = ngx_pnalloc(r->pool, strlen(bucket) + 1);
	strcpy(sm.bucket, bucket);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found bucket: %s", sm.bucket);

	// Check if we know anyhting about the bucket
	if ((! strcmp(sm.bucket, LOCATION_PUBLIC1)) || (! strcmp(sm.bucket, LOCATION_PUBLIC2))) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Bucket is public: %s", sm.uri);
	}
	else if (!strcmp(sm.bucket, LOCATION_PRIVATE)) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Bucket is private: %s", sm.uri);
	}
	else {
		// Return code to refuse processing so that other filters may kick in
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "URI %s invalid bucket %s", sm.uri, sm.bucket);
		return NGX_DECLINED;
	}

	// Get attachment/stream mode
	attachment = strtok(NULL, "/");
	sm.attachment = ngx_pnalloc(r->pool, strlen(attachment) + 1);
	strcpy(sm.attachment, attachment);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found download/stream: %s", sm.attachment);

	// Attachment flag based on URL
	if (!strcmp(attachment, DNLD_ATTACHMENT)) {
		sm.is_attachment = true;
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Download will be an attachmanet");
	}
	else if (!strcmp(attachment, DNLD_STREAM)) {
		sm.is_attachment = false;
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Download will be a stream");
	}
	else {
		// Return code to refuse processing so that other filters may kick in
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "URI %s invalid stream/download mode %s", sm.uri, attachment);
		return NGX_DECLINED;
	}

	// Get media ID
	id = strtok(NULL, "/");
	if (! id) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "URI %s file ID not found", sm.uri);
		return NGX_DECLINED;
	}
	sm.id = ngx_pnalloc(r->pool, strlen(id) + 1);
	strcpy(sm.id, id);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found file ID: %s", sm.id);

	// Etag from client If-None-Match
	if (r->headers_in.if_none_match) {
		sm.if_none_match = from_ngx_str(r->pool, r->headers_in.if_none_match->value);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Received ETag: %s", sm.if_none_match);
	}
	else
		sm.if_none_match = NULL;

	// Find web token:
	// - in cookie which name is stored in WEB_TOKEN, or
	// - in header 'Authorization' which values is "Bearer TOKEN"
	ngx_str_t cookie_name = ngx_string(WEB_TOKEN);
	ngx_str_t cookie_value = ngx_null_string;
	ngx_int_t rc = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &cookie_name, &cookie_value);
	if (rc != NGX_DECLINED) {
		sm.token = from_ngx_str(r->pool, cookie_value);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Web token found in cookie %s: %s", WEB_TOKEN, sm.token);
	}
	else {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Web token not found in cookie: %s", WEB_TOKEN);

		if (r->headers_in.authorization) {
			sm.authorization = from_ngx_str(r->pool, r->headers_in.authorization->value);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Found Authorization header: %s", sm.authorization);

			if (strstr(sm.authorization, "Bearer")) {
				sm.token = ngx_pcalloc(r->pool, strlen(sm.authorization) + 1);
				strncpy(sm.token, sm.authorization + 7, strlen(sm.authorization) - 7);
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Web token found in Authorization header: %s", sm.token);
			}
			else
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Web token not found in Authorization header");
		}
	}

	// Fill in MongoDB connection data struct
	mongo.conn = NULL;
	mongo.collection = NULL;
	mongo.cursor = NULL;
	mongo.gridfs = NULL;
	mongo.file = NULL;
	mongo.stream = NULL;
	mongo.jwt = NULL;
	bson_init (&mongo.filter);

	// Fill in MongoDB file data struct and set some defaults (to be used if no corresponding field is found)
	mongo_file.etag = NULL;
	mongo_file.md5 = NULL;
	mongo_file.filename = NULL;
	mongo_file.content_type = NULL;
	mongo_file.length = 0;
	mongo_file.upload_date = 0;
	mongo_file.access = 0;					// NB: Default access is "private"

	// Connect MongoDB
	mongo.conn = mongoc_client_new (sm.mongo_url);
	if (! mongo.conn) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to connect to MongoDB");
		cleanup_mongo(&mongo);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Define OID for media
	bson_oid_t oid_fid;
	bson_oid_init_from_string (&oid_fid, sm.id);

	// Define query for metadata: filter on metadata.fid (media ID)
	bson_append_oid (&mongo.filter, "metadata.fid", -1, &oid_fid);

	bson_tmp = bson_as_json(&mongo.filter, NULL);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Using BSON filter: %s", bson_tmp);
	bson_free(bson_tmp);

	// If Filesystem is enabled, try it first
	if (sm.fs_enabled) {
		// Get metadata from FS_METADATA_COLLECTION
		ret = get_metadata(&mongo, &mongo_file, &sm, r, FS_METADATA_COLLECTION);
		if (ret && (ret != NGX_HTTP_NOT_FOUND)) {
			cleanup_mongo(&mongo);
			return ret;
		}

		// Process the file (unless we got 404 previously)
		if (! ret) {
			// Init download data
			ret = init_grid_file(&mongo_file, &sm, &grid_file, r);
			if (ret) {
				cleanup_mongo(&mongo);
				return ret;
			}

			ret = read_fs(&mongo, &sm, &grid_file, r);
			if (ret) {
				cleanup_mongo(&mongo);
				return ret;
			}	

			// Send the file
			ret = send_file(&sm, &grid_file, r);

			// Unmap memory mapped for sending the file
			if (munmap(grid_file.data, grid_file.length) < 0)
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s munmap() error %u", sm.id, errno);

			cleanup_mongo(&mongo);
			return ret;
		}
	}

	// If GridFS is enabled, try it next
	if (sm.mongo_enabled) {
		// Get metadata from MONGO_COLLECTION_FILES
		ret = get_metadata(&mongo, &mongo_file, &sm, r, MONGO_COLLECTION_FILES);
		if (ret && (ret != NGX_HTTP_NOT_FOUND)) {
			cleanup_mongo(&mongo);
			return ret;
		}

		// Process the file
		if (! ret) { 
			// Init download data
			ret = init_grid_file(&mongo_file, &sm, &grid_file, r);
			if (ret) {
				cleanup_mongo(&mongo);
				return ret;
			}

			// Read the file
			ret = read_gridfs(&mongo, &sm, &grid_file, r);
			if (ret) {
				cleanup_mongo(&mongo);
				return ret;
			}

			// Send the file
			ret = send_file(&sm, &grid_file, r);
			cleanup_mongo(&mongo);
			return ret;
		}
	}

	// Return 404
	cleanup_mongo(&mongo);
	return NGX_HTTP_NOT_FOUND;
}

/**
 * Get file metadata from MongoDB
 */
ngx_int_t get_metadata(medicloud_mongo_t *mongo, medicloud_mongo_file_t *mongo_file, sm_t *sm, ngx_http_request_t *r, char *collection_name) {
	const char *bson_key, *bson_key_metadata;
	const bson_t *doc;
	bson_iter_t iter, metadata;
	int jwt_res;
	ngx_int_t ret;

	// Get file metadata
	mongo->collection = mongoc_client_get_collection (mongo->conn, sm->mongo_db, collection_name);
	if (! mongo->collection) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to get collection %s", collection_name);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// For newer mongoc driver vesions like 1.15 on EL8:
	bson_t *opts = BCON_NEW ("limit", BCON_INT64 (1));
	mongo->cursor = mongoc_collection_find_with_opts (mongo->collection, &mongo->filter, NULL, NULL);
	bson_destroy (opts);
	if (! mongo->cursor) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to get cursor for collection %s", collection_name);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (! mongoc_cursor_next (mongo->cursor, &doc)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Metadata for file %s not found in collection %s", sm->id, collection_name);
		return NGX_HTTP_NOT_FOUND;
	}

	if (! bson_iter_init (&iter, doc)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to initialise BSON iterator");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	while(bson_iter_next(&iter)) {
		bson_key = bson_iter_key (&iter);
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing file data key %s with type %i", bson_key, bson_iter_type(&iter));

		if ((! strcmp(bson_key, "md5")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			mongo_file->md5 = bson_iter_utf8 (&iter, NULL);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s found MD5: %s", sm->id, mongo_file->md5);
		}

		else if ((! strcmp(bson_key, "filename")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			mongo_file->filename = bson_iter_utf8 (&iter, NULL);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s found filename: %s", sm->id, mongo_file->filename);
		}

		else if ((! strcmp(bson_key, "contentType")) && (bson_iter_type(&iter) == BSON_TYPE_UTF8)) {
			mongo_file->content_type = bson_iter_utf8 (&iter, NULL);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s found content type: %s", sm->id, mongo_file->content_type);
		}

		else if (! strcmp(bson_key, "length")) {
			if (bson_iter_type(&iter) == BSON_TYPE_INT32)
				mongo_file->length = bson_iter_int32 (&iter);
			else if (bson_iter_type(&iter) == BSON_TYPE_INT64)
				mongo_file->length = bson_iter_int64 (&iter);
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s found length: %l", sm->id, mongo_file->length);
		}

		else if ((! strcmp(bson_key, "uploadDate")) && (bson_iter_type(&iter) == BSON_TYPE_DATE_TIME)) {
			mongo_file->upload_date = bson_iter_date_time (&iter) / 1000;
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s found upload date: %l", sm->id, mongo_file->upload_date);
		}

		else if ((! strcmp(bson_key, "metadata")) && (bson_iter_type(&iter) == BSON_TYPE_DOCUMENT)) {
			// Read the metadata child object
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s found metadata", sm->id);

			if (! bson_iter_recurse (&iter, &metadata)) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s unable to get metadata iterator", sm->id);
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}

			while(bson_iter_next(&metadata)) {
				bson_key_metadata = bson_iter_key (&metadata);
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing metadata key %s with type %i", bson_key_metadata, bson_iter_type(&metadata));

				if ((! strcmp(bson_key_metadata, "ETag")) && (bson_iter_type(&metadata) == BSON_TYPE_UTF8)) {
					mongo_file->etag = bson_iter_utf8 (&metadata, NULL);
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s found ETag: %s", sm->id, mongo_file->etag);
				}

				if ((! strcmp(bson_key_metadata, "tid")) && (bson_iter_type(&metadata) == BSON_TYPE_OID)) {
					bson_oid_to_string (bson_iter_oid(&metadata), mongo_file->tid);
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s found TID: %s", sm->id, mongo_file->tid);
				}

				if ((! strcmp(bson_key_metadata, "uid")) && (bson_iter_type(&metadata) == BSON_TYPE_OID)) {
					bson_oid_to_string (bson_iter_oid(&metadata), mongo_file->uid);
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s found UID: %s", sm->id, mongo_file->uid);
				}

				if ((! strcmp(bson_key_metadata, "access")) && (bson_iter_type(&metadata) == BSON_TYPE_INT32)) {
					mongo_file->access = bson_iter_int32 (&metadata);
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s found access: %i", sm->id, mongo_file->access);
				}
			}
		}
	}

	// Authorise request if private
	if (! mongo_file->access) {
		// Check if we have a web token, return 401 otherwise
		if (! sm->token) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Private file requested, but web token not found for URI %s", sm->uri);
			return NGX_HTTP_UNAUTHORIZED;
		}

		// Validate and extract the token	
		if ((jwt_res = jwt_decode(&mongo->jwt, sm->token, (unsigned char*)sm->jwt_key, strlen(sm->jwt_key)))) {
			if (jwt_res == EINVAL) {
				// Invalid signature
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s invalid signature", sm->token);
				ret = NGX_HTTP_UNAUTHORIZED;
			}
			else {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s system error %u while decoding", sm->token, jwt_res);
				ret = NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
			return ret;
		}

		sm->exp = jwt_get_grant_int(mongo->jwt, "exp");
		if (errno == ENOENT) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to find claim EXP", sm->token);
			return NGX_HTTP_UNAUTHORIZED;
		}
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Token %s found claim EXP %l", sm->token, sm->exp);
		if (sm->exp < time(NULL)) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s has expired: EXP is %l, now is %l", sm->token, sm->exp, time(NULL));
			return NGX_HTTP_UNAUTHORIZED;
		}

		sm->uid = jwt_get_grant(mongo->jwt, "uid");
		if (sm->uid) {
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Token %s found claim UID %s", sm->token, sm->uid);
		}
		else {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to find claim UID", sm->token);
			return NGX_HTTP_UNAUTHORIZED;
		}

		sm->tid = jwt_get_grant(mongo->jwt, "tid");
		if (sm->tid) {
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Token %s found claim TID %s", sm->token, sm->uid);
		}
		else {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Token %s unable to find claim TID", sm->token);
			return NGX_HTTP_UNAUTHORIZED;
		}

		// Check for UID match between token and file
		if (strcmp(mongo_file->uid, sm->uid)) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s does not belong to user %s", sm->id, sm->uid);
			return NGX_HTTP_UNAUTHORIZED;
		}
	}

	return 0;
}

/**
 * Init file for download
 */
ngx_int_t init_grid_file(medicloud_mongo_file_t *mongo_file, sm_t *sm, medicloud_grid_file_t *grid_file, ngx_http_request_t *r) {
	// Set ETag: use MD5 field if no ETag field found, use defailt if no MD5 field found
	if (mongo_file->etag) {
		grid_file->etag = ngx_pcalloc(r->pool, strlen(mongo_file->etag) + 1);
		strcpy(grid_file->etag, mongo_file->etag);
	}
	else if (mongo_file->md5) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s ETag not found, using MD5 %s", sm->id, mongo_file->md5);
		grid_file->etag = ngx_pcalloc(r->pool, strlen(mongo_file->md5) + 1);
		strcpy(grid_file->etag, mongo_file->md5);
	}
	else {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s ETag and MD5 not found, using default %s", sm->id, DEFAULT_ETAG);
		grid_file->etag = ngx_pcalloc(r->pool, strlen(DEFAULT_ETAG) + 1);
		strcpy(grid_file->etag, DEFAULT_ETAG);
	}

	// Compare file ETag with a supplied ETag, if any, and return 304 on match
	// NB: This will also match when weak check is requested (W/"1234567890")
	if (sm->if_none_match && strstr(sm->if_none_match, grid_file->etag)) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s has a match on ETag, sending 304", sm->id);
		return NGX_HTTP_NOT_MODIFIED;
	}

	// Set filename
	if (mongo_file->filename) {
		grid_file->filename = ngx_pcalloc(r->pool, strlen(mongo_file->filename) + 1);
		strcpy(grid_file->filename, mongo_file->filename);
	}
	else {
		grid_file->filename = ngx_pcalloc(r->pool, strlen(DEFAULT_FILENAME) + 1);
		strcpy(grid_file->filename, DEFAULT_FILENAME);
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s filename not found, using default %s", sm->id, DEFAULT_FILENAME);
	}

	// Set content type
	if (mongo_file->content_type) {
		grid_file->content_type = ngx_pcalloc(r->pool, strlen(mongo_file->content_type) + 1);
		strcpy(grid_file->content_type, mongo_file->content_type);
	}
	else {
		grid_file->content_type = ngx_pcalloc(r->pool, strlen(DEFAULT_CONTENT_TYPE) + 1);
		strcpy(grid_file->content_type, DEFAULT_CONTENT_TYPE);
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s content type not found, using default %s", sm->id, DEFAULT_CONTENT_TYPE);
	}

	// Set upload date
	if (mongo_file->upload_date)
		grid_file->upload_date = mongo_file->upload_date;
	else {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s unable to find upload date, using current time", sm->id);
		grid_file->upload_date = time(NULL);
	}

	// Set length
	if (mongo_file->length)
		grid_file->length = mongo_file->length;
	else {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s length not found ot empty file", sm->id);
		return NGX_HTTP_OK;
	}

	return 0;
}

/**
 * Read file from GridFS
 */
ngx_int_t read_gridfs(medicloud_mongo_t *mongo, sm_t *sm, medicloud_grid_file_t *grid_file, ngx_http_request_t *r) {
	bson_error_t mongo_error;
	int64_t bytes, pos=0;

	// Get GridFS handler
	mongo->gridfs = mongoc_client_get_gridfs (mongo->conn, sm->mongo_db, GRIDFS_COLLECTION_FILES, &mongo_error);
	if (! mongo->gridfs) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to get GridFS collection %s from DB %s: %s", GRIDFS_COLLECTION_FILES, sm->mongo_db, mongo_error.message);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Get file handler from GirdFS
	sprintf(mongo_error.message, "No error");
	// For newer mongoc driver versons like 1.15 on EL8
	mongo->file = mongoc_gridfs_find_one_with_opts (mongo->gridfs, &mongo->filter, NULL, &mongo_error);
	if (! mongo->file) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s not found in GridFS: %s", sm->id, mongo_error.message);
		return NGX_HTTP_NOT_FOUND;
	}

	// Get stream
	mongo->stream = mongoc_stream_gridfs_new (mongo->file);
	if (! mongo->stream) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s unable to get file stream", sm->id);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// TODO If possible, write directly to output to avoid double buffering?
	// Poll the stream until exhausted
	//grid_file->data = malloc(grid_file->length);
	grid_file->data = ngx_pnalloc(r->pool, grid_file->length);

	for (;;) {
		bytes = mongoc_stream_read (mongo->stream, grid_file->data + pos, grid_file->length, 1, 10000);

		if (bytes < 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s error reading from GridFS", sm->id);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		if (bytes == 0)
			break;

		pos += bytes;
	}

	if (pos != grid_file->length) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s expected %l bytes read %l bytes", sm->id, grid_file->length, bytes);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	return 0;
}

/**
 * Read file from Filesystem
 */
ngx_int_t read_fs(medicloud_mongo_t *mongo, sm_t *sm, medicloud_grid_file_t *grid_file, ngx_http_request_t *r) {
	// Get path
	int i, len, pos=0, fd;
	char *path;

	len = strlen(sm->fs_root) + 1 + 2 * sm->fs_depth + strlen(sm->id) + 1;
	path = ngx_pcalloc(r->pool, len);
	memset(path, '\0', len);

	memcpy(path, sm->fs_root, strlen(sm->fs_root));
	pos += strlen(sm->fs_root);

	memcpy(path + pos, "/", 1);
	pos ++;

	for (i=0; i < sm->fs_depth; i++) {
		memcpy(path + pos, sm->id + i, 1);
		pos ++;
		memcpy(path + pos, "/", 1);
		pos ++;
	}

	memcpy(path + pos, sm->id, strlen(sm->id));

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s using path: %s", sm->id, path);

	// Read the file: use mmap to map the physical file to memory
	if ((fd = open(path, O_RDONLY)) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s open() error %u", sm->id, path, errno);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if ((grid_file->data = mmap(NULL, grid_file->length, PROT_READ, MAP_SHARED, fd, 0)) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s mmap() error %u", sm->id, path, errno);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (close(fd) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s using path %s close() error %u", sm->id, path, errno);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	return 0;
}

/**
 * Send file to client
 */
ngx_int_t send_file(sm_t *sm, medicloud_grid_file_t *grid_file, ngx_http_request_t *r) {
	int b1_len, b2_len;
	char *encoded = NULL;
	bool curl_encoded = false;
	CURL *curl;
    ngx_buf_t *b;
    ngx_chain_t out;

	// ----- PREPARE THE HEADERS ----- //

	// HTTP status
	r->headers_out.status = NGX_HTTP_OK;

	// Content-Length
	r->headers_out.content_length_n = grid_file->length;

	// Content-Type 
	r->headers_out.content_type.len = strlen(grid_file->content_type);
	r->headers_out.content_type.data = (u_char*)grid_file->content_type;
	
	// Last-Modified
	r->headers_out.last_modified_time = grid_file->upload_date;

	// ETag
	b1_len = strlen(grid_file->etag) + 2;
	ngx_buf_t *b1 = ngx_create_temp_buf(r->pool, b1_len);
	b1->last = ngx_sprintf(b1->last, "\"%s\"", grid_file->etag);

	r->headers_out.etag = ngx_list_push(&r->headers_out.headers);
	r->headers_out.etag->hash = 1;
	r->headers_out.etag->key.len = sizeof(HEADER_ETAG) - 1;
	r->headers_out.etag->key.data = (u_char*)HEADER_ETAG;
	r->headers_out.etag->value.len = b1_len;
	r->headers_out.etag->value.data = b1->start;

	// Attachment: if is_attachment
	if (sm->is_attachment) {
		// URI-encode the file name?
		curl = curl_easy_init();
		if (curl) {
			encoded = curl_easy_escape(curl, grid_file->filename, strlen(grid_file->filename));
			if (encoded) {
				curl_encoded = true;
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "File %s using URI-encoded filename %s", sm->id, encoded);
			}
			else {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s unable to URI-encode filename %s", sm->id, grid_file->filename);
				encoded = grid_file->filename;
			}
		}
		else {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "File %s unable to init curl for URI-encoding", sm->id);
		}

		// Add Content-Disposition header
		// NB: We reuse the low of an existing, but unused standard header
		//headers['Content-Disposition'] = 'attachment; filename="' + encodeURIComponent(this.file.filename) + '";'
		b2_len = 23 + strlen(encoded);
		ngx_buf_t *b2 = ngx_create_temp_buf(r->pool, b2_len);
		b2->last = ngx_sprintf(b2->last, "attachment; filename=\"%s\"", encoded);

		r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
		r->headers_out.www_authenticate->hash = 1;
		r->headers_out.www_authenticate->key.len = sizeof(HEADER_CONTENT_DISPOSITION) - 1;
		r->headers_out.www_authenticate->key.data = (u_char*)HEADER_CONTENT_DISPOSITION;
		r->headers_out.www_authenticate->value.len = b2_len;
		r->headers_out.www_authenticate->value.data = b2->start;

		if (curl) {
			if (curl_encoded)
				curl_free(encoded);
			curl_easy_cleanup(curl);
		}
	}

	// Accept-ranges (not strictly necessary, but good to have)
	r->headers_out.accept_ranges = ngx_list_push(&r->headers_out.headers);
	r->headers_out.accept_ranges->hash = 1;
	r->headers_out.accept_ranges->key.len = sizeof(HEADER_ACCEPT_RANGES) - 1;
	r->headers_out.accept_ranges->key.data = (u_char*)HEADER_ACCEPT_RANGES;
	r->headers_out.accept_ranges->value.len = sizeof("none") - 1;
	r->headers_out.accept_ranges->value.data = (u_char*)"none";

	// ----- PREPARE THE BODY ----- //

	// Prepare output buffer
	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate response buffer");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Prepare output chain; hook the buffer
	out.buf = b;
	out.next = NULL; 

	// Fill the buffer
	b->pos = grid_file->data;
	b->last = grid_file->data + grid_file->length;
	b->memory = 1; 
	b->last_buf = 1; 

	// ----- SERVE CONTENT ----- //

	// Send headers
	ngx_http_send_header(r); 

	// Send the body, and return the status code of the output filter chain.
	ngx_int_t ret =  ngx_http_output_filter(r, &out);

	// ----- ADDITIONAL (TIME CONSUMING) TASKS AFTER SERVING THE CONTENT ----- //
	// Nothing so far

	return ret;
} 

/**
 * Helper: clean up Mongo data
 */
void cleanup_mongo(medicloud_mongo_t *mongo) {
	if (mongo->cursor)
		mongoc_cursor_destroy(mongo->cursor);
	if (mongo->collection)
		mongoc_collection_destroy(mongo->collection);
	if (mongo->stream)
		mongoc_stream_destroy(mongo->stream);
	if (mongo->file)
		mongoc_gridfs_file_destroy(mongo->file);
	if (mongo->gridfs)
		mongoc_gridfs_destroy(mongo->gridfs);
	if (mongo->conn)
		mongoc_client_destroy(mongo->conn);
	if (mongo->jwt)
		jwt_free(mongo->jwt);
	bson_destroy(&mongo->filter);
}

/**
 * Helper: convert Nginx string to normal
 */
char *from_ngx_str(ngx_pool_t *pool, ngx_str_t ngx_str) {
		if (! ngx_str.len)
			return NULL;

		char *ret = ngx_pcalloc(pool, ngx_str.len + 1);
		memcpy(ret, ngx_str.data, ngx_str.len);
		return ret;
}

