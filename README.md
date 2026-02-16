# Concepts

This is an Nginx module that implements optimised custom delivery of content with possible access authorisation (e.g., user files etc.). Using it is as easy as making a `GET`, `POST`, `PUT` or `DELETE` HTTP request.

The module performs all tasks needed to manage the content: upload, download and delete. One may still implement the uploads and deletions outside this module if desired (e.g. if custom post-processing of uploaded files like thumbnail generation is required); the CDN may be put in read-only mode in such case.

Various methods of authorisation, both internal and external, are available. It is also possible to use the CDN without authorisation (e.g., for public content).

Multuple CDN nodes may be connected to each other to form the desired replication topology (e.g. star, full mesh etc.).

The CDN URL for a file will be similar to `http://cdn.example.com/file-id`. The file ID consists of 16 letters and numbers, followed by a dot and an integer. A second dot and a short extension may be present if the file is a part of a pack of files (see below).

# Initialise

To create a blank filesystem storage, use `bin/mkcdn.sh`.

Several parameters pay be passed to this tool:
- `depth`: the depth of the directory tree (i.e. the number of nested levels with 16 subdirectories per level); for 50-100 million files or less, depth of 4 is usually sufficient; for larger instances, depths of 5 or 6 may be preferable.
- `root`: the apex of the directory tree
- `user`: the name of the system user that will be made the owner of the directories (usually the account under which Nginx runs).
- `group`: the name of the system group that will be set for the directories (usually the primary group under which Nginx runs).

Note that depth is mostly for admin's convenience and is not related to the actual number of files the CDN may store (for which there is no hard limit); for example, a depth of 4 means that with 10 million files, there will be about 150 files per directory. 

# Nginx configuration

All below Nginx parameters should be configured for the chosen `location`: 

## General parameters

Sampel values are illustrative.

- `cdn`: Enable CDN module (mandatory)
- `cdn_fs_root /opt/cdn`: Root directory of the CDN filesystem (mandatory)
- `cdn_fs_depth 4`: depth of the CDN tree (mandatory)
- `cdn_server_id 1`: the ID of the server instance, integer between 1 and 48 (optional, default 1)
- `cdn_vhost_id 2725a35b-fb7c-4aad-923d-cadf00fa292d`: the ID of the server instance, any string (optional, default "00000000")
- `cdn_cors_origin host.example.com`: Allowed CORS origin (optional, default *)
- `cdn_read_only yes`: Read-only mode prohibits uploads and deletions; set to `yes` to enable (optional, default "no")

## Authorisation parameters

- `cdn_matrix_upld`: Authorisation matrix for uploads (optional, default "allow:allow:deny:deny")
- `cdn_matrix_dnld`: Authorisation matrix for downloads (optional, default "allow:deny:deny:deny")
- `cdn_matrix_del`: Authorisation matrix for deletions (optional, default "allow:deny:deny:deny")
- `cdn_auth_type jwt`: Type of authorisation to use: `jwt` or `session` (optional, default none)
- `cdn_auth_cookie my_cookie`: Name of the cookie where to find the authorisation token (optional)
- `cdn_auth_header X-Custom-Auth`; Name of the HTTP header where to find the authorisation token (optional)
- `cdn_auth_filter filter_token,-,1`: Name of the filter and its parameters to apply to authorisation value (optional)
- `cdn_jwt_key string|path`: Only for authorisation `jwt` - either the JWT key as string or absolute path to a file with the public key in PEM
- `cdn_jwt_field user_id`: Only for authorisation `jwt`: Name of the JWT payload field which contains the authorisation value
- `cdn_request_type json`: Type of authorisation request to perform, one of `json`, `xml`, `mysql`, `postgresql`, `oracle`, `mongo`
- `cdn_all_cookies yes`: Only for request type `json` or `xml`: include all cookies in request to authorisation service
- `cdn_all_headers yes`: Only for request type `json` or `xml`: include all HTTP headers in request to authorisation service

## Transport parameters

- `cdn_transport_type unix`: Type of transport for authorisation, one of `unix`, `tcp`, `http`, `mysql`, `oracle`, `postgresql`, `mongo`, `redis`, `internal`, `none` or `preauth`
- `cdn_unix_socket /path/to/unix.sock`: Only for transport type `unix`: path to the Unix socket of the authorisation service
- `cdn_tcp_host`: only for transport type `tcp`: hostname of the authorisation service
- `cdn_tcp_port`: only for transport type `tcp`: port of the authorisation service
- `cdn_http_url`: only for transport type `http`: URL of the authorisation service
- `cdn_db_dsn DNS-or-URL`: only for transport type `mysql`, `oracle`, `postgresql`, `mongo`, `redis`: DSN of the database service (format is DB-specific, see below)
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

## Additional notes

### Server ID

Configuration parameter `cdn_server_id` defines the ID of the server when multiple CDN servers write to the same filesystem tree. It is used to guarantee the uniqueness of the uploaded file. Only used when uploading files via CDN. Default is 1.

### Virtual Host ID

Configuration parameter `cdn_vhost_id` defines the ID of the virtual host when multiple CDN virtual hosts share the same filesystem tree (e.g., one virtual host is used for writing to the CDN and another to reading from it). It is used to guarantee the uniqueness of the configuration. If not specified, the filesystem path to the apex of the directory tree will be used.

### CORS

For cross-origin resource sharing (CORS) one allowed host may be set in the `cdn_cors_origin` configuration parameter. The default value for it is "*" (allow any host).

# Build configuration

## Features

To enable/disable some of the features (mostly such that require external libraries to be compiled and run), edit src/modules.h and uncomment the respective line:

- JWT support
- Mongo support
- MySQL support
- Oracle support
- PostgreSQL support
- Redis support

## Platforms

The following tags are known to build on the below platforms:

- 0.16.x: RHEL-9 (nginx-1.20, libjwt-1.x, libxml2-2.9)
- 0.17.x: RHEL-10 (nginx-1.26, libjwt-3.x, libxml2-2.12)
- 0.18.x: RHEL-10 (nginx-1.26, libxml2-2.12, janssons-2.14-3, openssl-3.5.1-7)

# Authorisation

Authorisation is built from three components:

- Authorisation method: supported are JWT, session ID  and transparent (completely offloaded)
- Request type: specifies the format of the request that will be sent to the authorisation body: SQL, JSON, XML or MongoDB.
- Transport type: specifies the connection type to the authorisation body: MySQL, PostgreSQL, Oracle, Mongo, Redis, Internal, HTTP, TCP, Unix domain socket as well as the special pre-authorised (preauth) type.

## Method

Authorisation token may be supplied in:

- Authorization header, as `Bearer <token>` (default)
- In custom header: set its name in configuration option `cdn_auth_header`
- In a cookie: set its name in configuration option `cdn_auth_cookie`

The authorisation method determines how this authentication token will be processed to extract the actual authorisation token, which is then passed to the authorisation backend. 

With transparent authorisation all incoming headers and cookies are passed verbatim to the authorisation body.

## Matrix

An authorisation request has 3 possible outcomes:

- Explicit status code (with file metadata in the case of download authorisation)
- No status code (with file metadata in the case of download authorisation)
- Empty response

In the first case the request will be allowed or denied based on the explicit status value in the response. In the second and third cases, the `cdn_matrix_upld`, `cdn_matrix_dnld` and `cdn_matrix_del` configuration parameters may override the built-in logic whether to allow or deny the request - for file uploads, downloads and deletions respectively. 

### Upload

If defined, the `cdn_matrix_upld` configuration parameter must be a colon-delimited list of 4 actions, each either `allow` or `deny`. They will be applied in the given order to the following cases: 

- Authorisation value is present and the authorisation request yielded non-empty response (without a `status` field); default is `allow`.
- Authorisation value is present and the authorisation request yielded empty response; default is `allow`.
- Authorisation value is missing and the authorisation request yielded non-empty response (without a `status` field); default is `deny`.
- Authorisation value is missing and the authorisation request yielded empty response; default is `deny`.

### Download

If defined, the `cdn_matrix_dnld` configuration parameter must be a colon-delimited list of 4 actions, each either `allow` or `deny`. They will be applied in the given order to the following cases: 

- Authorisation value is present and the authorisation request yielded non-empty response (without a `status` field); default is `allow`.
- Authorisation value is present and the authorisation request yielded empty response; default is `deny`.
- Authorisation value is missing and the authorisation request yielded non-empty response (without a `status` field); default is `deny`.
- Authorisation value is missing and the authorisation request yielded empty response; default is `deny`.

### Deletion

If defined, the `cdn_matrix_del` configuration parameter must be a colon-delimited list of 4 actions, each either `allow` or `deny`. They will be applied in the given order to the following cases: 

- Authorisation value is present and the authorisation request yielded non-empty response (without a `status` field); default is `allow`.
- Authorisation value is present and the authorisation request yielded empty response; default is `deny`.
- Authorisation value is missing and the authorisation request yielded non-empty response (without a `status` field); default is `deny`.
- Authorisation value is missing and the authorisation request yielded empty response; default is `deny`.

## Authorisation by JWT

The authorisation token is a JWT, which is extracted and validated to obtain the authorisation value. This is the recommended method.

To use this method, set the configuration option `cdn_auth_type` to `jwt`.

Also, set the JWT signature verification key in configuration option `cdn_jwt_key`: if using a symmetric key, set in directly in the configuration; if using a public key, enter the path to its file. The CDN will not use fully-encrypted JWT.

Finally, specify the JWT payload field to use for authorisation in configuration option `cdn_jwt_field`.

The JWT must have a claim named `exp`, containing the Unix timestamp for the expiration time of the token. Expired requests will be denied.

## Authorisation by session ID

The authorisation token is a session ID, which used as authorisation value. This method is not recommended. 

To use this method, set the configuration option `cdn_auth_type` to `session`.

As the session ID has neither a digital signature nor expiration time, its validity should be verified by the authorisation body; this means authorisation by session ID is only useful (security-wise) with transparent authorisation (see next).

## Transparent authorisation

This method sends extra information to the authorisation body, which may be:

- All HTTP headers, if configuration option `cdn_all_headers` is set to `yes`.
- All cookies, if configuration option `cdn_all_cookies` is set to `yes`.

This method will automatically include in the request the authorisation value if configuration option `cdn_auth_type` is set to either `jwt` or `session`.

This method may be used with some complex request types like `json` or `xml`. It is not applicable for SQL or Mongo request type.

## Authorisation value filters

If the authorisation value needs processing, you may configure a filter to be applied to it. The name of the filter and its parameters are given as comma-separated list in the `cdn_auth_filter` configuration parameter.

The following filters are currently defined:

- `filter_token`: splits the authorisation value by a single-byte delimiter and returns the N-th token. First parameter is the delimiter, second parameter is which token to return (first is 1, second is 2 etc.). If the delimiter is not found, the authorisation value is retained as-is. If the delimiter is found, but not as many time as requested in token count, the authorisation value is reset to NULL, which may deny the request.

# Request types

## Common parameters

The following parameter names are used throughout this document (both for requests and responses):

- `http_method`: string, the name of the HTTP method used like `POST`, `PUT`, `GET`, `DELETE`. Uses capital letters.
- `auth_value`: string, the authentication value (e.g., user ID) extracted from the authorisation token, if any
- `file_id`: string, the ID for the file that is being uploaded, downloaded or deleted
- `filename`: string, the original filename; default is `file`
- `content_type`: string, content type for the file; default is `application/octet-stream`
- `content_disposition"`: string, content disposition; if set to `attachment`, the file will be served as attachment; default is to serve inline.
- `etag`: string, the eTag for the file; default is `00000000000000000000000000000000`
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

NB: The parameter value must be a valid a JSON. All double quotes must be escaped when putting the string in the Nginx configuration!

The default filter is `{"file_id": "%s", "auth_value": "%s"}`.

### Delete

The CDN will compose and execute the same query as with download. The document, if found, will be deleted.

## JSON

This request type can be used with transport type set to `unix` (Unix socket), `tcp` (TCP socket) or `http` (HTTP request).

NB: The CDN modules uses libbson to create and parse JSON. This library expects strings (e.g., file name) to be valid UTF-8. If not, the request will likely fail. Note that there are technically valid UTF-8 sequences (like 0x96) which are not valid UTF-8 characters (as, in this example, it is a control character). 

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

Set the DSN in the configuration option `cnd_db_dsn` using the following syntax: `hostname:port:username:password:database`. If the host is `localhost`, you may put the full path to the Unix socket instead of port number; fields `username`, `password` and `database` are ignored.

## MySQL

This transport is only useful when request type is set to `mysql`.

Set the DSN in the configuration option `cnd_db_dsn` using the following syntax: `hostname:port:username:password:database`. If the host is `localhost`, you may put the full path to the Unix socket instead of the port.

## PostgreSQL

This transport is only useful when request type is set to `postgresql`.

Set the DSN in the configuration option `cnd_db_dsn` using the following syntax: `postgresql://user:password@hostname:port/dbname`.

## Oracle

This transport is only useful when request type is set to `oracle`.

Set the DSN in the configuration option `cnd_db_dsn` the same way as for MySQL (see above); field `host` should be a valid TNS record with a hostname and a service, typically in the format `hostname/service`; fields `port` and `database` are ignored. Note that since the `:` is a delimited, it cannot be part of the service name, i.e. you cannot specify a TCP port as a part of the service name. Oracle's default TCP port is 1521.

You need to manually install Oracle Instant Client library; make sure the chosen version knows how to talk to the Oracle server. `LD_LIBARY_PATH` may need to be exported with the path to the client library directory.

You also need the OCI library from https://github.com/vrogier/ocilib. In order for this library to work, at runtime the `ORACLE_HOME` variable needs to be exported; it shoudl also be whitelisted in Nginx by adding `env ORACLE_HOME` to the top level of the Nginx configuration file for the CDN.

## MongoDB

Only useful when request type is set to `mongo`.

Set the database connection string in the configuration option `cnd_db_dsn` using the standard MongoDB driver syntax following syntax: `mongodb://user:password@hostname:port[,more-hosts-if-replicaset]/database?options` where `options` may include such as `replicaSet=some_name` or `authSource=some_database`. 

## Internal

This transport is usually used when request type is `json` (JSON file format, preferred) or `xml` (XML file format).

The metadata will be saved into a local file alongside the uploaded file itself, as either JSON (preferred as it is faster) or XML.

There are no configuration options for this transport.

To enable the in-memory cache of metadata, set the `cdn_cache_size` to the desired amount in MB; default value is 0 (meaning cache is disabled). Each cached entry consumes around 3 KB of memory (when the allocated amount is exhausted, oldest entry will be evicted from the cache). Note that the cache is per-thread (of Nginx).

## Preauth

This transport is useful to organise access to content wuth pre-authorised URL.

There are no configuration options for this transport.

This transport matches the `auth_value` to the `file_id`; if the `auth_value` is missing, or if the two do not match, the request is denied. For this reason, this transport only works for downloads.

No metadata is returned by this transport, so the file is served verbatim.

## None

This transport discards the authorisation request and always returns OK. It can be used on public instances usually combined with `auth_type: none`.

There are no configuration options for this transport.

No metadata is returned by this transport, so the file is served verbatim.

# File uploads

## Uploads via CDN

File upload uses HTTP POST request. Only one file can be uploaded per request. The file may have to be accompanied by an authorisation token as per the chosen configuration (e.g., signed JWT with proper authorisation value and `exp` claim in the `Bearer` field of the `Authorization` header).

The following upload methods are available via CDN:

- `multipart/form-data`: only raw data (aka 8-bit) and Base64 encoding are supported (i.e. no quoted-printable or other encodings).
- `application/x-www-form-urlencoded`

The following form field names are recognised: 

- `d`: file field when uploading using `multipart/form-data`; the file content when using `application/x-www-form-urlencoded`.
- `n`: original filename; mandatory for `application/x-www-form-urlencoded`; for `multipart/form-data` overrides the value, provided in the file part of the form itself.
- `ct`: content type of the file; mandatory for `application/x-www-form-urlencoded`; for `multipart/form-data` overrides the value, provided in the file part of the form itself.
- `cd`: content disposition to use for this file. If set to `attachment`, the file will be served as attachment; for any other value (or if missing) the file will be served inline.
- `pl`: the file ID of the pack leader, which must exist in the CDN. Only when using file packs (see below).
- `ext`: the extension to file ID of the pack leader for this specific file. Only when using file packs (see below). Limited to 16 bytes, alpha-numeric only.

The metadata can be created in two ways:

- For SQL or MongoDB, `auth_value` must be provided to be set in the database table or collection, e.g. via JWT.
- For JSON or XML, a request will be send using the chosen transport (Unix, TCP, HTTP) with the file metadata (as in the response when asking to download or delete a file); the response will be ignored.

## Concurrent versions

Although the CDN uses large hashing depth (128 bit) and an algorithm with sigh sensitivity and dispersion, as with every hashing method conflicts are inevitable. To adapt, the CDN will append a dot and a counter value to the hash when creating the file ID. This way, different files with the same may still co-exist on the CDN.

## File packs

Normally, every uploaded file will get its own ID, computed by the CDN. Sometimes it may be necessary to use an existing ID instead, followed by an extension. An example would be storing multiple copies of the same image, but with different resolution; in this case, the base file ID (called here "pack leader") will be provided to the web client and, based on its needs, it will request this file ID, amended by a specific extension.

To upload the pack leader, just do a regular upload and save the provided ID.

To upload any subsequent file to the pack, add the `pl` and the `ext` parameters to the upload:

`pl` must be the file ID of the pack leader
`ext` must be a custom extension for this specific file

The CDN will return the file ID of the newly uploaded file, which will be the ID of the pack leader, followed by a dot and the provided extension.

To retrieve a file from the pack, just use its full ID as returned by the CDN.

When getting a file, if the file ID contains an extension, but the file is not found, the CDN will attempt to serve the pack leader instead.

Note that the extensions will be converted to base16 before being written to the filesystem; this is a security measure. The file ID of a pack member will contain the extension in its original form.

## Manual uploads

Here is the workflow to upload a file to the CDN:

### Create a file ID

- Use a lightweight hashing algorithm. 
- We recommend strongly 128-bit murmur3: very fast, very sensitive, very good distribution, open source.
- Ensure input is unique: use the file name, the current timestamp (with at least ms precision), the ID (or session ID) of the user and an ID of the app instance (e.g., IP address).
- Convert the ID to lowercase hex string. Append a dot and a counter value (start at zero, increment by one for each existing file with the same hash).
- If uploading packs, select an extension and convert it to base16. Append to the file ID after a dot.
- Do not use random data: low entropy on virtualised systems will slow the CDN down.

### Write the file ID and its metadata

Write them to the metadata storage which will be used by CDN for authorisation (e.g., to the MySQL database); include all the fields that will be needed for download.

Test the custom authorisation query to make sure metadata is properly returned.

### Write the file into CDN file structure

- Read the first N letters of the file ID generated above (where N is the depth of the CDN tree).
- Use each of these N letters as one directory level.
- Place the file in the resulting path.
- Example: with depth of 4, file ID `abcdef0123456789` must be placed at path `/a/b/c/d/abcdef0123456789` inside the CDN root (note that the first N letters are *not* removed form the file name, they just form the path - this is how path will be determined when the CDN needs to serve the file).

### Example

The `examples` directory contains a sample file upload server in NodeJS.

# File download

To get a file from the CDN, issue a `GET` HTTP request to the CDN endpoint, followed by the file ID, e.g. `http://cdn.example.com/file-id`. The request must be accompanied by an authorisation token as per the chosen configuration (e.g., signed JWT with proper authorisation value and `exp` claim in the `Bearer` field of the `Authorization` header).

# File deletion

To delete a file from the filesystem, issue the same request as for downloading the file, but use DELETE HTTP method.

NB: The metadata for the file will be deleted when using internal authorisation, SQL authorisation or MongoDB. In all other cases the authorisation body should delete the metadata (the `http_method` in the authorisation request will be set to `DELETE`).

# Replication

The CDN files may be mirrored in any way desired (e.g., rsync). 

To only transfer files that were changed and to avoid the need to compare both sides file by file, the CDN keeps a transaction log with all changes. The log file is written as plain text file inside the CDN and is rotated on the top of every hour. The file name is `<prefix>YYYYMMDDHH` where the date is always in UTC and the prefix can be set in the `cdn_index_prefix` configuration options (the default is `______`). 

The file is tab-delimited with two fields: single letter for the operation (I - file inserted, U - file updated, D - file deleted) and the ID of the file. 

To automatically purge old replication log files, put the `cdn_instance.sh` into the cron and put and configure its config file `/etc/cdn/instance.d/XYZ.conf` (an example file is provided).

The remote side may retrieve the list from the previous hour and then fetch the inserted or updated files and also remove the deleted files. To do so, put the `cdn_mirror.sh` into the cron of the remote side and add one config file per remote CDN instance in `/etc/cdn/mirror.d/XYZ.conf` (an example file is provided). On its first run, the script will create the initial savepoint file in `/var/lib/cdn/mirror.d/XYZ.conf` with the following line, containing the date and hour (in UTC) from which to start the replication:

`SAVEPOINT=YYYYMMDDHH`

Using the mirroring script requires a separate virtual host in Nginx on the master instance. It should not have the CDN module loaded, but instead it should just provide direct access to the whole file tree for the CDN instance (i.e. the web root of the virtual host should be set to the filesystem root of the CDN instance). As this provides unauthenticated access to all CDN files without any authorisation imposed, make sure access to this virtual host is only allowed from the IP addresses of the replica CDN instances.

# Compliance

The CDN supports a number of HTTP headers that govern the file delivery:
- If-None-Match: an eTag that will be compared with the one of the file and on match 304 will be returned
- If-Modified-Since: a timestamp that will be compared with the one of the file and on match 304 will be returned
- If-Range: an eTag or timestamp that will be compared with the one of the file; on match, partial download as per the Range header with HTTP code 206 will be performed; on no match, full download with HTTP code 200 will be performed.
- Range: one or more ranges of the file that will be served with HTTP 206 code (instead of a full file download).

# Examples

`unix_socket_server.js` is an example Unix socket server in Node.js which can be used as a skeleton for creating an authorisation body. It contains the necessary code minus the actual authorisation part. The server can easily be adapted to use TCP socket.

`file_upload.js` is an example HTTP server in Node.js which can be used as a skeleton for creating an upload service for the CDN. It contains the necessary code minus the authorisation of the upload and the writing of the metadata.

# Development environment setup

NB: This is for RHEL-10 and derivatives.

```
# Go to checkout dir

# Install build tools and basic dependencies
yum groupinstall -y 'Development Tools'
yum install -y nginx libcurl-devel pcre-devel

# JWT support requires Jansson and OpenSSL.
# yum install jansson-devel openssl-devel

# XML suport requries libXML
# yum install libxml2-devel libxml-devel libxslt-devel

# MySQL/MariaDB support requires Connector-C:
# yum install mariadb-connector-c-devel

# PostgreSQL requires their client library
# yum install libpq-devel

# Oracle support requries Oracle Instant Client and the OCI library.
# wget https://github.com/vrogier/ocilib/releases/download/v4.6.3/ocilib-4.6.3-gnu.tar.gz
# OCIlib needs to know where to find Oracle Instant Client at runtime, so export ORACLE_HOME for it, e.g.:
# export ORACLE_HOME=/ora01/app/oracle/product/11.2.0/dbhome_1
# To link against OCIlib, Oracle Instant Client's library directry must be in the LD path, so export LD_LIBRARY_PATH for it, e.g.:
# export LD_LIBRARY_PATH=$ORACLE_HOME/lib

# MongoDB requires BSON support and a MongoDB connector
# yum install libbson-devel mongo-c-driver-devel

# To enable/disable support for various authentications and transports, edit src/modules.h.

# Copy our module config
cp support-files/nginx/modules/* /usr/share/nginx/modules

# Get the Nginx sources (version must match the installed one from RPM)
wget http://nginx.org/download/nginx-1.26.3.tar.gz
gunzip nginx-1.26.3.tar.gz
tar xf nginx-1.26.3.tar
cd nginx-1.26.3

# Configure the build the same way as the RPM package does
# NB: This command does not include the additional transports and authorisations; add them to the $EXTRA_INCLUDES and $EXTRA_LIBS, e.g.:
#EXTRA_INCLUDES="-I /usr/include/libbson-1.0 -I/usr/include/libxml2"
#EXTRA_LIBS="-ljansson -lcrypto -lxml2"

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
--with-compat \
--with-debug \
--with-file-aio \
--with-http_addition_module \
--with-http_auth_request_module \
--with-http_dav_module \
--with-http_degradation_module \
--with-http_flv_module \
--with-http_gunzip_module \
--with-http_gzip_static_module \
--with-http_image_filter_module=dynamic \
--with-http_mp4_module \
--with-http_perl_module=dynamic \
--with-http_random_index_module \
--with-http_realip_module \
--with-http_secure_link_module \
--with-http_slice_module \
--with-http_ssl_module \
--with-http_stub_status_module \
--with-http_sub_module \
--with-http_v2_module \
--with-http_v3_module \
--with-http_xslt_module=dynamic \
--with-mail=dynamic \
--with-mail_ssl_module \
--with-openssl-opt=enable-ktls \
--with-pcre \
--with-pcre-jit \
--with-stream=dynamic \
--with-stream_realip_module \
--with-stream_ssl_module \
--with-stream_ssl_preread_module \
--with-threads \
--with-cc-opt=-"O2 -flto=auto -ffat-lto-objects -fexceptions -g -grecord-gcc-switches -pipe -Wall -Wno-complain-wrong-lang -Werror=format-security -Wp,-U_FORTIFY_SOURCE,-D_FORTIFY_SOURCE=3 -Wp,-D_GLIBCXX_ASSERTIONS -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -fstack-protector-strong -specs=/usr/lib/rpm/redhat/redhat-annobin-cc1  -m64 -march=x86-64-v3 -mtune=generic -fasynchronous-unwind-tables -fstack-clash-protection -fcf-protection -mtls-dialect=gnu2 $EXTRA_INCLUDES" \
--with-ld-opt="-Wl,-z,relro -Wl,--as-needed  -Wl,-z,pack-relative-relocs -Wl,-z,now -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -specs=/usr/lib/rpm/redhat/redhat-annobin-cc1  -Wl,--build-id=sha1 -Wl,-E -O2 $EXTRA_LIBS"

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

# Upload a file (or a pack leader) from command-line
curl -X POST -F n=test.jpg -F ct='image/jpeg' -F d=@test.jpg  http://cdn.example.com

# Upload a pack member from command-line
curl -X POST -F n=test-800x600.jpg -F ct='image/jpeg' -F pl=0123456789abcdef.0 -F ext=800x600 -F d=@test-800x600.jpg  http://cdn.example.com

# Get an uploaded file
curl -o test-dnld.jpg http://cdn.example.com/438fcf2c4d4eec4d92acc96dcaaa7940

# Update an uploaded file
curl -X PUT -F n=test2.jpg -F ct='image/jpeg' -F d=@test2.jpg  http://cdn.example.com/438fcf2c4d4eec4d92acc96dcaaa7940
```

