# Concept

The module implements an optimised, custom delivery of authorised content (e.g., user files etc.). Using it is as easy as making a `GET`, `POST` or `DELETE` HTTP request.

The module performs all tasks needed to manage the content: upload, download and delete. You may still implement the uploads and deletions yourself if preferred (e.g. if a custom post-processing of uploaded files like thumbnail generation is required); the CDN may be put in read-only mode in this case.

Each file request for must be authorised before served. Authorisation is handled by an external body to which the module connects. The authorisation body should return some file metadata for an approved download.

The business logic for authorisation consists of three main elements:

- Authorisation method: we support JWT, session ID  and transparent (completely offloaded)
- Request type: specifies the format of the request that will be sent to the external authorisation body; we support SQL, JSON, XML and Mongo.
- Transport type: specifies how to connect to the external authorisation body; we support MySQL, PostgreSQL, Oracle, Mongo, Redis, Internal, HTTP, TCP and Unix domain socket.

# Initialise

To create a blank filesystem storage, use `tools/mkcdn.sh`.

# Nginx configuration

All below Nginx parameters should be configured for the chosen `location`: 

## General parameters

- `cdn`: Enable CDN module (mandatory)
- `cdn_fs_root /opt/cdn`: Root directory of the CDN filesystem (mandatory)
- `cdn_fs_depth 4`: depth of the CDN tree (mandatory)
- `cdn_server_id 1`: the ID of the server instance, integer between 1 and 48 (optional, default 1)
- `cdn_cors_origin host.example.com`: Allowed CORS origin (optional, default *)
- `cdn_read_only no`: Read-only mode prohibits uploads and deletions; set to `yes` to enable (optional, default "no")

## Authorisation parameters

- `cdn_matrix_upld`: Authorisation matrix for uploads (optional, default "allow:allow:deny:deny")
- `cdn_matrix_dnld`: Authorisation matrix for downloads (optional, default "allow:deny:deny:deny")
- `cdn_matrix_del`: Authorisation matrix for deletions (optional, default "allow:deny:deny:deny")
- `cdn_auth_type jwt`: Type of authorisation to use: `jwt` or `session` (optional, default none)
- `cdn_auth_cookie my_cookie`: Name of the cookie where to find the authorisation token (optional)
- `cdn_auth_header X-Custom-Auth`; Name of the HTTP header where to find the authorisation token (optional)
- `cdn_auth_filter filter_token,-,1`: Name of the filter and its parameters to apply to authorisation value (optional)
- `cdn_jwt_key 0123456789ABCDEF`: Only for authorisation `jwt` - either the JWT key or absolute path to a file with the key
- `cdn_jwt_field user_id`: Only for authorisation `jwt`: Name of the JWT payload field which contains the authorisation value
- `cdn_request_type json`: Type of authorisation request to perform, one of `json`, `xml`, `mysql`, `postgresql`, `oracle`, `mongo`
- `cdn_all_cookies yes`: Only for request type `json` or `xml`: include all cookies in request to authorisation service
- `cdn_all_headers yes`: Only for request type `json` or `xml`: include all HTTP headers in request to authorisation service

## Transport parameters

- `cdn_transport_type unix`: Type of transport for authorisation, one of `unix`, `tcp`, `http`, `mysql`, `oracle`, `postgresql`, `mongo`, `redis`, `internal`
- `cdn_unix_socket /path/to/unix.sock`: Only for transport type `unix`: path to the Unix socket of the authorisation service
- `cdn_tcp_host`: only for transport type `tcp`: hostname of the authorisation service
- `cdn_tcp_port`: only for transport type `tcp`: port of the authorisation service
- `cdn_http_url`: only for transport type `http`: URL of the authorisation service
- `cdn_db_dsn dsn-or-url`: only for transport type `mysql`, `oracle`, `postgresql`, `mongo`, `redis`: DSN of the database service (format is DB-specific, see below)
- `cdn_sql_insert`: only for transport type `mysql`, `oracle`, `postgresql`: SQL query to execute when uploading a file (with placeholders)
- `cdn_sql_select`: only for transport type `mysql`, `oracle`, `postgresql`: SQL query to execute when fetching a file (with placeholders)
- `cdn_sql_delete`: only for transport type `mysql`, `oracle`, `postgresql`: SQL query to execute when deleting a file (with placeholders)
- `cdn_mongo_collection`: only for transport type `mongo`: name of the Mongo collection which stored the metadata
- `cdn_mongo_db`: only for transport type `mongo`: name of the Mongo database with the metadata collection
- `cdn_mongo_filter`: only for transport type `mongo`: the filter for metadata collection query (with placeholders)
- `cdn_cache_size`: only for transport type `internal`: the size of the memory cache to use in MB; default: 0 (cache disabled)

The following general-purpose Nginx params may be useful:

- `client_body_buffer_size`: sets the size above which a temp file will be used for uploads; default is 16k, you may want to increase it.
- `client_max_body_size`: sets the maximum size of a single POST request used for uploads to CDN (i.e. larger files will not be accepted for upload); default is 1m, you may want to increase it.

The CDN URL for a file will be similar to `http://cdn.example.com/some-file-id`

## Additional notes

### Server ID

Configuration parameter `cdn_server_id` denotes the ID of the server when multiple CND servers write to the same filesystem tree. It is used to guarantee the uniqueness of the uploaded file. Only used when uploading files via CDN. Default is 1.

### CORS

For cross-origin resource sharing (CORS) you configure one allowed host in the `cdn_cors_origin` configuration parameter. The default value for it is "*" (allow any host).

# Build configuration

To enable/disable some of the features (mostly such that require external libraries to be compiled and run), edit src/modules.h and uncomment the respective line:

- JWT support
- Mongo support
- MySQL support
- Oracle support
- PostgreSQL support
- Redis support

# Authorisation

## Method

Authorisation token may be supplied in:

- Authorization header, as `Bearer <token>` (default)
- In custom header: set its name in configuration option `cdn_auth_header`
- In a cookie: set its name in configuration option `cdn_auth_cookie`

The authorisation method determines how this authentication token will be processed to extract the actual authorisation token, which is then passed to the authorisation backend. 

You may also use transparent authorisation when we pass all incoming headers and cookies to the authorisation body without working on them.

## Matrix

An authorisation request has 3 possible outcomes:

- Explicit status code (with file metadata in the case of download authorisation)
- No status code (with file metadata in the case of download authorisation)
- Empty response

In the first case the request will be allowed or denied based on the explicit status value in the response. In the second and third cases, the `cdn_matrix_upld`, `cdn_matrix_dnld` and `cdn_matrix_del` configuration parameters may override the built-in logic whether to allow or deny the request - for file uploads, downloads and deletions respectively. 

### Upload

If defined, the `cdn_matrix_upld` configuration parameter must be a colon-delimited list of 4 actions, each either `allow` or `deny`. They will be applied in the given order to the following cases: 

- Authorisation request with authorisation value yielded non-empty response without `status` field; default is `allow`.
- Authorisation request with authorisation value yielded empty response; default is `allow`.
- Authorisation request without authorisation value yielded non-empty response without `status` field; default is `deny`.
- Authorisation request without authorisation value yielded empty response; default is `deny`.

### Download

If defined, the `cdn_matrix_dnld` configuration parameter must be a colon-delimited list of 4 actions, each either `allow` or `deny`. They will be applied in the given order to the following cases: 

- Authorisation request with authorisation value yielded non-empty response without `status` field; default is `allow`.
- Authorisation request with authorisation value yielded empty response; default is `deny`.
- Authorisation request without authorisation value yielded non-empty response without `status` field; default is `deny`.
- Authorisation request without authorisation value yielded empty response; default is `deny`.

### Deletion

If defined, the `cdn_matrix_del` configuration parameter must be a colon-delimited list of 4 actions, each either `allow` or `deny`. They will be applied in the given order to the following cases: 

- Authorisation request with authorisation value yielded non-empty response without `status` field; default is `allow`.
- Authorisation request with authorisation value yielded empty response; default is `deny`.
- Authorisation request without authorisation value yielded non-empty response without `status` field; default is `deny`.
- Authorisation request without authorisation value yielded empty response; default is `deny`.

## Authorisation by JWT

In this case the authorisation token is a JWT, which is extracted and validated to obtain the authorisation value.

To use this method, set the configuration option `cdn_auth_type` to `jwt`.

Also, set the JWT signature verification key in configuration option `cdn_jwt_key`; you may also set the full path to the file that has the key instead.

Finally, specify the JWT payload field to use for authorisation in configuration option `cdn_jwt_field`.

The JWT must have a claim named `exp`, containing the Unix timestamp for the expiration time of the token.

For JWT you'll need the JWT decoding library: https://github.com/benmcollins/libjwt

## Authorisation by session ID

In this case the authorisation token is a session ID, which used as authorisation value. As the session ID has no digital signature nor expiration time, its validity should be verified by the authorisation body; this means authorisation by session ID is only useful with transparent authorisation.

To use this method, set the configuration option `cdn_auth_type` to `session`.

## Transparent authorisation

This method allows you to send some extra info to the authorisation body. This extra info may be:

- All HTTP headers, if configuration option `cdn_all_headers` is set to `yes`.
- All cookies, if configuration option `cdn_all_cookies` is set to `yes`.

This method will automatically include in the request the authorisation value if configuration option `cdn_auth_type` is set to either `jwt` or `session`.

This method may be used with some complex request types like `json` or `xml`. It is not applicable for SQL or Mongo request type.

## Authorisation value filters

If the authorisation value needs processing, you may configure a build-in filter to be applied to it. The name of the filter and its parameters are given as comma-separated list in the `cdn_auth_filter` configuration parameter.

The following filters are currently defined:

- `filter_token`: splits the authorisation value by a single-byte delimiter and returns the N-th token. First parameter is the delimiter, second parameter is which token to return (first is counted as 1, second as 2 etc.). If delimiter is not found, the authorisation value is retained as-is. If the delimiter is found, but not as many time as requested in token count, the authorisation value is reset to NULL, which will deny the request.

# Request types

## Common parameters

The following parameter names are used throughout this document (both for requests and responses):

- `http_method`: string, the name of the HTTP method used like `POST`, `PUT`, `GET`, `DELETE`. Uses capital letters.
- `auth_value`: string, the authentication value (e.g., user ID) extracted from the authorisation token, if any
- `file_id`: string, the ID for the file that is being uploaded, downloaded or deleted
- `filename`: string, the original filename; default is `file`
- `content_type`: string, content type for the file; default is `application/octet-stream`
- `content_disposition"`: string, content disposition; if set to `attachment`, the file will be served as attachment; default is to serve inline.
- `etag`: string, the Rtag for the file; default is `00000000000000000000000000000000`
- `status`: int, HTTP-style code; use `200` or `304` to approve request, `403` to deny it, `500` to denote processing error
- `error`: string, will be logged by Nginx if the `status` code indicates an error

## SQL (MySQL, PostgreSQL, Oracle)

Set the request type according to the SQL engine - `mysql`, `postgresql` or `oracle`. 

Set the transport to the same value.

### Upload

Set the SQL INSERT query to run in the configuration option `cdn_sql_insert`. It may have up to eight placeholders which will be filled with the following values in the given order: `auth_value`, `file`, `filename`, `content_type`, `content_disposition`, `etag`. All these placeholders should be `'%s'` (for strings); don't forget the single quotes around the string placeholder. If the authorisation value is not found in the request, it will be substituted by an empty string.

NB: for complex queries, create a stored procedure and use stanza like `CALL my_procedure('%s', '%s', '%s', %u, '%s', '%s', %u, '%s')`.

The query may return a row (e.g., if using a stored procedure or if using `INSERT ... RETRUNING`) having a column `status` (or `STATUS` for Oracle) with the HTTP code to allow or deny the operation. 

The default query is `REPLACE INTO cdn (auth_value, file_id, filename, content_type, content_disposition, etag) VALUES ('%s','%s','%s','%s','%s','%s')`.

### Update

Uses the same configuration as for the upload.

Make sure the file ID is a UNIQUE key in the database and use REPLACE in the `cdn_sql_insert` statement so that the metadata may get updated. 

### Download

Set the SQL SELECT query to run in the configuration option `cdn_sql_select`. It may have up to two `%s` placeholders - the first will be filled with the file ID and the second - with the authorisation value.

NB: for complex queries, create a stored procedure and use stanza like `CALL my_procedure(%s, %s)`.

NB: Oracle returns the column names in caps. This is OK.

The default query is `SELECT * FROM cdn WHERE file_id='%s' AND auth_value='%s'`.

### Delete

Set the SQL DELETE query to run in the configuration option `cdn_sql_delete`. It must have a single `%s` placeholder, which will be filled with the file ID.

NB: for complex queries, create a stored procedure and use stanza like `CALL my_procedure(%s)`.

The default query is `DELETE FROM cdn WHERE file_id='%s'`.

## MongoDB

This request type can only be used with transport type set to `mongo` (Mongo).

Set the database name in the configuration option `cnd_mongo_db`. Set the collection name the configuration option `cnd_mongo_collection`.

Because MongoDB does not allow for textual queries, both file metadata and authorisation data must reside in a single collection with one document per file.

### Upload

The CDN will create a document with the same properties as given, including `file_id`, containing the ID of the file to be served by the CDN and `auth_value`, containing the value that will be used by the CDN to authorise access to the file (e.g., user ID or group ID etc.). 

### Update

Same as with the upload. An existing document will be updated.

### Download

Set the Mongo filter in the configuration option `cdn_mongo_filter`. It may have up to two `%s` placeholders - the first will be filled with the file ID and the second - with the authorisation value.

NB: The parameter value must be a valid a JSON. You must escape all double quotes when putting the string in the Nginx configuration!

The default filter is `{"file_id": "%s", "auth_value": "%s"}`.

### Delete

The CDN will compose and execute the same query as with download. The document, if found, will be deleted.

## JSON

This request type can be used with transport type set to `unix` (Unix socket), `tcp` (TCP socket) or `http` (HTTP request).

### Upload

*Request format*

```
{
	"http_method": "POST",
	"auth_value": "12345",
	"file_id": "1234-567-89",
	"filename": "myfile.jpg",
	"content_type": "image/jpeg",
	"content_disposition": "attachment",
	"etag": "12345678901234567890123456789012",
}
```

*Response format*

```
{
	"status": 200
}
```

If the response lacks the `status` field, but has a `auth_value`, it will be compared to the authorisation value in the HTTP request, if such is present, and on mismatch the response will be treated as empty.

### Delete

The request will be the same as with upload, but the `http_method` will be set to PUT.

The response should be the same as with upload.

### Download 

*Request format*

Field `headers` is only included if configuration option `cdn_all_headers` is set to `yes`.

Field `cookies` is only included if configuration option `cdn_all_cookies` is set to `yes`.

The field `auth_value` from authentication token is included only if configuration option `cdn_auth_type` is set to either `jwt` or `session`.

```
{
	"file_id" : "1234-567-89",
	"http_method" : "GET"
	"auth_value" : "12345"
	"headers" : [
		{
			"name": "Some-Header",
			"value": "some-value",
		},
		...
	],
	"cookies": [
		{
			"name": "some_cookie_name",
			"value": "some_cookie_value"
		},
		...
	]
}
```

*Response format*

```
{
	"status": 200,
	"filename": "myfile.jpg",
	"content_type": "image/jpeg",
	"content_disposition": "attachment",
	"etag": "12345678901234567890123456789012",
	"error": "none"
}
```

If the response lacks the `status` field, but has a `auth_value`, it will be compared to the authorisation value in the HTTP request, if such is present, and on mismatch the response will be treated as empty.

### Delete

The authorisation request will be the same as with download, but the `http_method` will be set to DELETE.

The response should be the same as with upload.

## XML

This request type can be used with transport type set to `unix` (Unix socket), `tcp` (TCP socket) or `http` (HTTP request).

### Upload

*Request format*

```
<request>
	<http_method>POST</http_method>
	<auth_value>12345</auth_value>
	<file_id>1234-567-89</file_id>
	<filename>myfile.jpg</filename>
	<content_type>image/jpeg</content_type>
	<content_disposition>attachment</content_disposition>
	<etag>12345678901234567890123456789012</etag>
</request>
```

*Response format*

```
<response>
	<status>200</status>
</response>
```

If the response lacks the `status` element, but has a `auth_value`, it will be compared to the authorisation value in the HTTP request, if such is present, and on mismatch the response will be treated as empty.

### Delete

The request will be the same as with upload, but the `http_method` will be set to PUT.

The response should be the same as with upload.

### Download

*Request format*

Element `headers` is only included if configuration option `cdn_all_headers` is set to `yes`.

Element `cookies` is only included if configuration option `cdn_all_cookies` is set to `yes`.

The element `auth_value` from authentication token is included only if configuration option `cdn_auth_type` is set to either `jwt` or `session`.

```
<request>
	<http_method>GET</http_method>
	<auth_value>12345</auth_value>
	<file_id>1234-567-89</file_id>
	<headers>
		<header>
			<name>Some-Header</name>
			<value>some-value</value>
		</header>
		...
	</headers>
	<cookies>
		<cookie>
			<name>some_cookie_name</name>
			<value>ome_cookie_value</value>
		</cookie>
		...
	</cookies>
</request>
```

*Response format*

```
<response>
	<status>200</status>
	<filename>myfile.jpg</filename>
	<content_type>image/jpeg</content_type>
	<content_disposition>attachment</content_disposition>
	<etag>12345678901234567890123456789012</etag>
	<error>none</error>
</response>
```

If the response lacks the `status` element, but has a `auth_value`, it will be compared to the authorisation value in the HTTP request, if such is present, and on mismatch the response will be treated as empty.

### Delete

The authorisation request will be the same as with download, but the `http_method` will be set to DELETE.

The response should be the same as with upload (only status code, but mandatory).

# Transport types

## Unix socket

This transport is used when request type is `json` (JSON exchange) or `xml` (XML exchange).

Set the path to the Unix socket in configuration option `cdn_unix_socket`. Note that socket must be writeable by the Nginx system user. 

The Unix socket must be of type `stream`. The module will half-close the connection once it has written its request and will then expect the response, followed by full connection close by the authorisation body. 

NB: The `examples` directory contains a sample Unix domain socket server in NodeJS which shows socket half-closing.

## TCP socket

This transport is used when request type is `json` (JSON exchange) or `xml` (XML exchange).

Set the host and port for TCP connection in configuration options `cdn_tcp_host` and `cdn_tcp_port`.

The module will half-close the connection once it has written its request and will then expect the response, followed by full connection close by the authorisation body. 

NB: TCP is naturally slower than Unix domain socket.

NB: The `examples` directory contains a sample Unix domain socket server in NodeJS which shows socket half-closing. It can easily be adapted to TCP socket.

## HTTP

This transport is used when request type is `json` (JSON exchange) or `xml` (XML excahnge).

Set the URL in configuration option `cdn_http_url`. If using HTTPS, the local libcurl (used to make the HTTP request) must be able to verify the TLS certificate of the remote end. Authentication to this URL is currently unsupported.

The HTTP request will be of type POST.

NB: HTTP is naturally slower than both Unix domain socket an TCP socket.

## Redis

This transport is usually used when request type is `json` (JSON file format, preferred) or `xml` (XML file format).

The metadata will be saved into a Redis instance as either JSON (preferred as it is faster) or XML.

Set the DSN in the configuration option `cnd_db_dsn` using the following syntax: `hostname:port:username:password:database`. If you host is `localhost`, you may put the full path to the Unix socket instead of port number; fields `username`, `password` and `database` are ignored.

## Internal

This transport is usually used when request type is `json` (JSON file format, preferred) or `xml` (XML file format).

The metadata will be saved into a local file alongside the uploaded file itself, as either JSON (preferred as it is faster) or XML.

There are no configuration options for this transport.

To enable the in-memory cache of metadata, set the `cdn_cache_size` to the desired amount in MB; default value is 0 (meaning cache is disabled). Each cached entry consumes around 3 KB of memory (when the allocated amount is exhausted, oldest entry will be evicted from the cache).

NB: The cache is global (for all CDN instances that have it enabled), so its size will only be set once - therefore, if you want to use the cache for multiple CDN instances, make sure you have the same size set in each one (this will be the shared global cache size).

## MySQL

This transport is only useful when request type is set to `mysql`.

Set the DSN in the configuration option `cnd_db_dsn` using the following syntax: `hostname:port:username:password:database`. If you host is `localhost`, you may put the full path to the Unix socket in the `port` field.

## PostgreSQL

This transport is only useful when request type is set to `postgresql`.

Set the DSN in the configuration option `cnd_db_dsn` using the following syntax: `postgresql://user:password@hostname:port/dbname`.

## Oracle

This transport is only useful when request type is set to `oracle`.

Set the DSN in the configuration option `cnd_db_dsn` just like you would do for MySQL above; field `host` should be a valid TNS record with a hostname and a service, typically in the format `hostname/service`; fields `port` and `database` are ignored. Note that since the `:` is a delimited, it cannot be part of the service name, i.e. you cannot specify a TCP port as a part of the service name. Oracle's default TCP port is 1521.

You'll need to manually install Oracle Instant Client library; make sure you have a version which knows how to talk to your Oracle server. You will likely need to export `LD_LIBARY_PATH` with the path to the client library directory.

You'll also need the OCI library from https://github.com/vrogier/ocilib. In order for this library to work, at runtime you'll need to export the `ORACLE_HOME` variable. You also must whitelist this environment variable in Nginx by adding `env ORACLE_HOME` to the top level of your Nginx configuration file.

## MongoDB

Only useful when request type is set to `mongo`.

Set the database connection string in the configuration option `cnd_db_dsn` using the standard MongoDB driver syntax following syntax: `mongodb://user:password@hostname:port[,more-hosts-if-replicaset]/database?options` where `options` may include such as `replicaSet=some_name` or `authSource=some_database`. 

# File uploads

## Uploads via CDN

Files can be uploaded via the CDN itself. File upload uses HTTP POST request. Only one file can be uploaded per request. The file must be accompanied by an authorisation token as per the chosen configuration (e.g., signed JWT with proper authorisation value and `exp` claim in the `Bearer` field of the `Authorization` header).

The following upload methods are available via CDN:

- `multipart/form-data`: only raw data (aka 8-bit) and Base64 encoding are supported (i.e. no quoted-printable or other encodings).
- `application/x-www-form-urlencoded`

The following form field names are recognised: 

- `d`: file field when uploading using `multipart/form-data`; the file content when using `application/x-www-form-urlencoded`.
- `n`: original filename; mandatory for `application/x-www-form-urlencoded`; for `multipart/form-data` overrides the value, provided in the file part of the form itself.
- `ct`: content type of the file; mandatory for `application/x-www-form-urlencoded`; for `multipart/form-data` overrides the value, provided in the file part of the form itself.
- `cd`: content disposition to use for this file. If set to `attachment`, the file will be served as attachment; for any other value (or if missing) the file will be served inline.

The metadata can be created in two ways:

- For SQL or MongoDB, you need to provide `auth_value` to be set in the database table or collection, e.g. via JWT.
- For JSON or XML, a request will be send using the chosen transport (Unix, TCP, HTTP) with the file metadata (as in the response when asking to download or delete a file); the response will be ignored.

## Manual uploads

Here is the workflow to upload yourself a file to the CDN:

### Create file ID

- Use a lightweight hashing algorithm. 
- We recommend strongly 128-bit murmur3: very fast, very sensitive, very good distribution, open source.
- Ensure input is unique: use the file name, the current timestamp (with at least ms precision), the ID (or session ID) of the user and an ID of the app instance (e.g., IP address).
- Convert the ID to lowercase hex string.
- Do not use random data: low entropy on virtualised systems will slow you down.

### Write the file ID and its metadata

Write them to the metadata storage which will be used by CDN for authorisation (e.g., to the MySQL database); include all teh fields that will be needed for download.

Test your authorisation query to make sure metadata is properly returned.

### Write the file into CDN file structure

- Read the first N letters of the file ID generated above (where N is the depth of the CDN tree).
- Use each of these N letters as one directory level.
- Place the file in the resulting path.
- Example: with depth of 4, file ID `abcdef0123456789` must be placed at path `/a/b/c/d/abcdef0123456789` inside the CDN root (note that the first N letters are *not* removed form the file name, they just form the path - this is how path will be determined when the CDN needs to serve the file).

### Example

The `examples` directory contains a sample file upload server in NodeJS.

# File download

To get a file from the CDN, issue a `GET` HTTP request to the CDN endpoint, followed by the file ID, e.g. `http://cdn.example.com/some-file-id`. The request must be accompanied by an authorisation token as per the chosen configuration (e.g., signed JWT with proper authorisation value and `exp` claim in the `Bearer` field of the `Authorization` header).

# File deletion

To delete a file from the filesystem, issue the same request as for downloading the file, but use DELETE HTTP method.

NB: The metadata for the file will be deleted when using internal authorisation, SQL authorisation or MongoDB. In all other cases the authorisation body should delete the metadata (the `http_method` in the authorisation request will be set to `DELETE`).

# Examples

`unix_socket_server.js` is an example Unix socket server in Node.js which can be used as a skeleton for creating an authorisation body. It contains the necessary code minus the actual authorisation part. The server can easily be adapted to use TCP socket.

`file_upload.js` is an example HTTP server in Node.js which can be used as a skeleton for creating an upload service for the CDN. It contains the necessary code minus the authorisation of the upload and the writing of the metadata.

# Development environment setup

NB: This is for RHEL-8 and derivatives. RHEL-7 has some differences in packages and in the configure command. 

```
# Go to checkout dir

# Install build deps
yum groupinstall -y 'Development Tools'
yum install -y nginx libbson-devel libcurl-devel pcre-devel libxml2-devel libxml-devel libxslt-devel gd-devel gperftools-devel mariadb-connector-c-devel perl-ExtUtils-Embed

# Install libjwt from https://github.com/benmcollins/libjwt

# To have Oracle support, install Oracle Instant Client and the OCI library from wget https://github.com/vrogier/ocilib/releases/download/v4.6.3/ocilib-4.6.3-gnu.tar.gz
# OCIlib needs to know where to find Oracle Instant Client at runtime, so export ORACLE_HOME for it, e.g.:
# export ORACLE_HOME=/ora01/app/oracle/product/11.2.0/dbhome_1
# To link against OCIlib, Oracle Instant Client's library directry must be in the LD path, so export LD_LIBRARY_PATH for it, e.g.:
# export LD_LIBRARY_PATH=$ORACLE_HOME/lib

# To enable/disable MySQL and Oracle support, edit src/modules.h. Also there you can toggle JWT support.

# Copy our module config
cp support-files/nginx/modules/* /usr/share/nginx/modules

# Get the Nginx sources (version must match the installed one from RPM)
wget http://nginx.org/download/nginx-1.14.1.tar.gz
gunzip nginx-1.14.1.tar.gz
tar xf nginx-1.14.1.tar
cd nginx-1.14.1

# Configure the build the same way as the RPM packages does
# NB: This command has only includes and libraries for JWT and MySQL enabled - 
# and not for PostgreSQL, Oracle, Mongo and Redis
CFLAGS=-Wno-error ./configure \
--add-dynamic-module=../src \
--prefix=/usr/share/nginx \
--sbin-path=/usr/sbin/nginx \
--modules-path=/usr/lib64/nginx/modules \
--conf-path=/etc/nginx/nginx.conf \
--error-log-path=/var/log/nginx/error.log \
--http-log-path=/var/log/nginx/access.log \
--http-client-body-temp-path=/var/lib/nginx/tmp/client_body \
--http-proxy-temp-path=/var/lib/nginx/tmp/proxy \
--http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi \
--http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi \
--http-scgi-temp-path=/var/lib/nginx/tmp/scgi \
--pid-path=/run/nginx.pid \
--lock-path=/run/lock/subsys/nginx \
--user=nginx \
--group=nginx \
--with-file-aio \
--with-ipv6 \
--with-http_ssl_module \
--with-http_v2_module \
--with-http_realip_module \
--with-http_addition_module \
--with-http_xslt_module=dynamic \
--with-http_image_filter_module=dynamic \
--with-http_sub_module \
--with-http_dav_module \
--with-http_flv_module \
--with-http_mp4_module \
--with-http_gunzip_module \
--with-http_gzip_static_module \
--with-http_random_index_module \
--with-http_secure_link_module \
--with-http_degradation_module \
--with-http_slice_module \
--with-http_stub_status_module \
--with-http_perl_module=dynamic \
--with-http_auth_request_module \
--with-mail=dynamic \
--with-mail_ssl_module \
--with-pcre \
--with-pcre-jit \
--with-stream=dynamic \
--with-stream_ssl_module \
--with-debug \
--with-cc-opt='-O2 -g -pipe -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS -fexceptions -fstack-protector-strong -grecord-gcc-switches -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -specs=/usr/lib/rpm/redhat/redhat-annobin-cc1 -m64 -mtune=generic -fasynchronous-unwind-tables -fstack-clash-protection -fcf-protection -I /usr/include/libbson-1.0 -I /usr/include/mysql -I/usr/include/libxml2' \
--with-ld-opt='-Wl,-z,relro -Wl,-z,now -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -Wl,-E -lbson-1.0 -lcurl -ljwt -lmysqlclient -lxml2'

# Build modules only
make modules

# Copy our module to Nginx tree
cp objs/ngx_http_cdn_module.so /usr/lib64/nginx/modules

# Configure Nginx location in its config file /etc/nginx/nginx.conf

# Restrat nginx
systemctl restart nginx

# Create empty CDN tree using tools/mkcdn.sh
mkdir /opt/cdn
mkcdn.sh --root /opt/cdn --depth 4 --user nginx --group nginx

# Upload a file from command-line
curl -X POST -F n=test.jpg -F ct='image/jpeg' -F d=@test.jpg  http://cdn.example.com

# Get an uploaded file
curl -o test-dnld.jpg http://cdn.example.com/438fcf2c4d4eec4d92acc96dcaaa7940

# Update and upoaded file
curl -X PUT -F n=test2.jpg -F ct='image/jpeg' -F d=@test2.jpg  http://cdn.example.com/438fcf2c4d4eec4d92acc96dcaaa7940
```

