# Concept

The module implements an optimised, custom delivery of authorised content (e.g., user files etc.). 

The module only serves files (including deletion of files). Their upload must be handled separately; it is quite easy, though - see File Uploads below.

Each file request must be authorised before served. Authorisation is handled by an external body to which the module connects. 

The business logic for authorisation consists of two main elements:

- Authorisation method: we support JWT, session ID  and transparent (completely offloaded)
- Request type: specifies the format of the request that will be sent to the external authorisation body; we support SQL, JSON, XML and Mongo.
- Transport type: specifies how to connect to the external authorisation body; we support MySQL, Oracle, Mongo, HTTP, TCP and Unix domain socket.

# Initialise

To create a blank filesystem storage, use `tools/mkcdn.sh`.

# Nginx configuration

CDN URL for a file should be similar to `http://cdn.example.com/some-file-id`

```
location /
	cdn;                                // Enable CDN module
	cdn_server_id 1;                    // ID of the server instance, 1-48 (optional, default 1)
	cdn_fs_root /usr/share/curaden/fs;  // Root directgory of CDN 
	cdn_fs_depth 4;                     // CDN tree depth
	cdn_cors_origin host.example.com;   // Allowerd CORS origin (optional, default *)

	cdn_auth_type;                      // Type of authorisation to use: "jwt", "session" (optional)
	cdn_auth_cookie my_cookie;          // Cookie where to find the authorisation token (optional)
	cdn_auth_header X-Custom-Auth;      // HTTP header where to find the authorisation token (optional)
	cdn_jwt_key 0123456789ABCDEF;       // Authorisation "jwt": JWT key authorisation token
	cdn_jwt_field user_id;              // Authorisation "jwt": Name of the JWT payload field which contains the authorisation value

	cdn_request_type json;              // Type of authorisation request to perform: "json", "xml", "sql", "mongo"
	cdn_all_cookies yes;                // Request "json", "xml": include all cookies in request to authentication service
	cdn_all_headers yes;                // Request "json", "xml": include all HTTP headers in request to authentication service

	cdn_transport_type unix;            // Type of transport for authorisation: "unix", "tcp", "http", "mysql", "oracle", "mongo"
	cdn_unix_socket /path/to/unix.sock; // Transport "unix": path to the Unix socket of the authorisation service
	cdn_tcp_host;                       // Transport "tcp": hostname of the authorisation service
	cdn_tcp_port;                       // Transport "tcp": port of the authorisation service
	cdn_http_url;                       // Transport "http": URL of the authorisation service
	cdn_db_dsn dsn-or-url               // Transport "mysql", "oracle", "mongo": DSN of the database service (see docs for db-specific format)
	cdn_sql_select                      // Transport "mysql", "oracle": SQL query to execute when fetching a file (with placeholders)
	cdn_sql_delete                      // Transport "mysql", "oracle": SQL query to execute when deleting a file (with placeholders)
	cdn_mongo_collection                // Transport "mongo": name of the Mongo collection where the metadata is
	cdn_mongo_db                        // Transport "mongo": name of the Mongo database where the metadata collection is

```

## Server ID

Configuration parameter `cdn_server_id` denotes the ID of the server when multiple CND servers write to the same filesystem tree. It is used to guarantee the uniqueness of the uploaded file. Only used when uploading files via CDN. Default is 1.

## CORS

For cross-origin resource sharing (CORS) you configure one allowed host in the `cdn_cors_origin` configuration parameter. The default value for it is "*" (allow any host).

# Build configuration

To enable/disable some of the features (mostly such that require external libraries to be compiled and run), edit src/modules.h and comment/uncomment the respective line:

- JWT support
- Mongo support
- MySQL support
- Oracle support

# Authorisation method

Authorisation token may be supplied in:

- Authorization header, as `Bearer <token>` (default)
- In custom header: set its name in configuration option `cdn_auth_header`
- In a cookie: set its name in configuration option `cdn_auth_cookie`

The authorisation method determines how this authentication token will be processed to extract the actual authorisation token, which is then passed to the authorisation backend. 

You may also use tarnsparent authorisation when we pass all incoming headers and cookies to the authorisation body without working on them.

## Authorisation by JWT

In this case the authorisation token is a JWT, which is extracted and validated to obtain the authorisation value.

To use this method, set the configuration option `cdn_auth_type` to `jwt`.

Also, set the JWT signature verification key in configuration option `cdn_jwt_key`.

Finally, specify the JWT payload field to use for authorisation in configuration option `cdn_jwt_field`.

For JWT you'll need the JWT decoding library: https://github.com/benmcollins/libjwt

## Authorisation by session ID

In this case the authorisation token is a session ID, which used as authorisation value. As the session ID has no digital signature nor expiration time, its validity should be verified by the authorisation body.

To use this method, set the configuration option `cdn_auth_type` to `session`.

## Transparent authorisation

This method allows you to send some extra info to the authorisation body. This extra info may be:
- All HTTP headers, if configuration option `cdn_all_headers` is set to `yes`.
- All cookies, if configuration option `cdn_all_cookies` is set to `yes`.

This method will automatically include in the request the authorisation value if configuration option `cdn_auth_type` is set to either `jwt` or `session`.

This method may be used with some complex request types like JSON or XML. It is not applicable for SQL request type.

# Request types

## JSON

This request type is usually used with transport type set to `unix` (Unix socket) or `tcp` (TCP socket).

### Request format

Field `headers` is only included if configuration option `cdn_all_headers` is set to `yes`.

Field `cookies` is only included if configuration option `cdn_all_cookies` is set to `yes`.

The field `auth_value` from authentication token is included only if configuration option `cdn_auth_type` is set to either `jwt` or `session`.

The field `http_method` will be either `GET` for GET/HEAD HTTP requests or `DELETE` for DELETE HTTP requests.

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
		{
			"name": "Other-Header",
			"value": "other-value"
		},
		...
	],
	"cookies": [
		{
			"name": "some_cookie_name",
			"value": "some_cookie_value"
		},
		{
			"name": "other_cookie_name",
			"value": "other_cookie_value"
		},
		...
	]
}
```

### Response format

```
{
	"status": int, optional, http code; use 200, 304, 404, 500; if missing, file will be served if found (unless 304 can be returned), else 404
	"filename": string, optional, the file name to give the user; the value of "file" will be used if missing
	"content_type": string, optional, "application/octet-stream" will be used if missing
	"content_dispostion": string, optional, if set to "attachment", "attachment" will be used; else file will be served inline (default)
	"etag": string, optional, "00000000000000000000000000000000" will be used if missing
	"length": int, optional, stat() wil be used if missing
	"upload_date": int, optional, Unix timestamp of mtime; stat() wil be used if missing
	"error"	: string, optional, will be logged by Nginx
}
```

## XML

This request type is usually used with transport type set to `unix` (Unix socket) or `tcp` (TCP socket).

### Request format

Element `headers` is only included if configuration option `cdn_all_headers` is set to `yes`.

Element `cookies` is only included if configuration option `cdn_all_cookies` is set to `yes`.

The element `auth_value` from authentication token is included only if configuration option `cdn_auth_type` is set to either `jwt` or `session`.

The element `http_method` will be either `GET` for GET/HEAD HTTP requests or `DELETE` for DELETE HTTP requests.

```
<request>
	<file_id>1234-567-89</file_id>
	<http_method>12345</http_method>
	<auth_value>12345</auth_value>
	<headers>
		<header>
			<name>Some-Header</name>
			<value>some-value</value>
		</header>
		<header>
			<name>Other-Header</name>
			<value>other-value</value>
		</header>
		...
	</headers>
	<cookies>
		<cookie>
			<name>some_cookie_name</name>
			<value>ome_cookie_value</value>
		</cookie>
		<cookie>
			<name>other_cookie_name</name>
			<value>other_cookie_value</value>
		</cookie>
		...
	</cookies>
</request>
```

### Response format

See the JSON section above for fields meaning and values.

```
<response>
	<status></status>
	<filename></filename>
	<content_type></content_type>
	<content_dispostion></content_dispostion>
	<etag></etag>
	<length></length>
	<upload_date></upload_date>
	<error></error>
</response>
```

## SQL

Set the SQL queries to run in the configuration option `cnd_sql_select` (used to authorise a get or delete request) and `cdn_sql_delete` (used to delete metadata when deleting a file). It must have two `%s` placeholders - the first will be filled with the file ID and the second - with the value, extracted from the JWT payload.

The SQL query should return a single row with column names matching the keys in the JSON response above.

NB: Oracle returns the column names in caps. This is OK.

NB: for complex queries, create a stored procedure and use stanza like `CALL my_procedure(%s, %s)`.

## MongoDB

Because MongoDB does not allow for textual queries, both file metadata and authorisation data must reside in a single collection with one document per file. Each document must have the same properties as the JSON response above plus two extra: `file_id`, containing the ID of the file to be served by the CDN and `auth_value`, containing the value that will be used by the CDN to authorise access to the file (e.g., user ID or group ID etc.). When asking for authorisation and data, CDN will compose a Mongo query with a filter that will have both these properties set: `{file_id: 1234-567-89, auth_value: abcd-efgh-ijkl}`; there should either be one exact match (if access is authorised) or no match.

Set the database name in the configuration option `cnd_mongo_db`. Set the collection name the configuration option `cnd_mongo_collection`.

# Transport types

## Unix socket

Set the path to the Unix socket in configuration option `cdn_unix_socket`. Note that socket must be writable by the Nginx user. 

This transport is usually used when request type is `json` (JSON exchange) or `xml` (XML exchange).

The Unix socket must be of type `stream`. The module will half-close the connection once it has written its request and will then expect the response, followed by full connection close by the authorisation body. 

NB: The `examples` directory contains a sample Unix domain socket server in NodeJS which supports socket half-closing.

## TCP socket

Set the host and port for TCP connection in configuration options `cdn_tcp_host` and `cdn_tcp_port`.

This transport is usually used when request type is `json` (JSON exchange) or `xml` (XML excahnge).

The module will half-close the connection once it has written its request and will then expect the response, followed by full connection close by the authorisation body. 

NB: TCP is naturally slower than Unix domain socket.

NB: The `examples` directory contains a sample Unix domain socket server in NodeJS which supports socket half-closing. It can easily be converted to TCP socket.

## HTTP

Set the URL in configuration option `cdn_http_url`. If using HTTPS, the local libcurl (used to make the HTTP request) must be able to verify the TLS certificate of the remote end. Authentication to this URL is currently unsupported.

This transport is usually used when request type is `json` (JSON exchange) or `xml` (XML excahnge).

The HTTP request will be of type POST.

NB: HTTP is naturally slower than both Unix domain socket an TCP socket.

## MySQL

Set the DSN in the configuration option `cnd_db_dsn` using the following syntax: `host:port:username:password:database`. If you host is `localhost`, you may put the full path to the Unix socket instead of port number.

## Oracle

Set the DSN in the configuration option `cnd_db_dsn` just like you would do for MySQL above; field `host` should be a valid TNS record with a hostname and a service, typically in the format `hostname/service` fields `port` and `database` are ignored.

You'll need to manually install Oracle Instant Client library; make sure you have a version which knows how to talk to your Oracle server.

You'll also need the OCI library from https://github.com/vrogier/ocilib. In order for this library to work, at runtime you'll need to export the ORACLE_HOME variable.

## MongoDB

Set the database connection string in the configuration option `cnd_db_dsn` using the standard MongoDB driver syntax following syntax: `mongodb://user:password@hostname:port[,more-hosts-if-replicaset]/database?options` where `options` may include such as `replicaSet=some_name` or `authSource=some_database`. 

# File uploads

## Uploads via CDN

Files can be uploaded via the CDN itself. File upload uses HTTP POST request. Only one file can be uploaded per request.

The following upload methods are available via CDN:

- multipart/form-data
- application/x-www-form-urlencoded

The following form field names are recognised: 

- `f`: file field when uploading using multipart/form-data; the file content when using application/x-www-form-urlencoded.
- `n`: file name; only used for application/x-www-form-urlencoded.
- `cd`: content disposition to use for this file. May only be set to `attachment`, all other values are ignored. If not set, file will be served inline.
- `ct`: content type of the file. For multipart/form-data overrides the value, provided in the file part of the form itself.

The metadata can be created in two ways:

- For SQL or MongoDB, you need to provide auth_value to be set in the database table or collection, e.g. via JWT.
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

Write them to the metadata storage which will be used by CDN for authorisation (e.g., to the MySQL database).

- Original file name. Will be used when serving the file with `Attachment` disposition. 
- Upload timestamp. Will be compared to `If-Modified-Since` request header.
- Etag: will be used for `Etag` response header and compared to `If-None-Match` request header.
- MIME type. Will be used as `Content-Type`.
- Content disposition – serve inline or as attachment.
- Size: file size in bytes.

Test your authorisation query to make sure metadata is properly returned.

### Write the file into CDN file structure

- Read the first N letters of the file ID generated above (where N is the depth of the CDN tree).
- Use each of these N letters as one directory level.
- Place the file in the resulting path.
- Example: with depth of 4, file ID `abcdef0123456789` must be placed at path `/a/b/c/d/abcdef0123456789` inside the CDN root (note that the first N letters are *not* removed form the file name, they just for the path - this is how path will be determined when the CDN needs to serve the file).

### Example

See Examples below.

# File deletion

To delete a file from the filesystem, issue the same request as for getting a file, but use DELETE HTTP method.

NB: The metadata for the file will be deleted when using SQL authorisation or MongoDB. In al other cases the authorisation body should delete the metadata (when the `http_method` in the authorisation request is set to `DELETE`).

# Examples

`unix_socket_server.js` is an example Unix socket server in Node.js which can be used as a skeleton for creating an authorisation body. It contains the necessary code minus the actual authorisation part.

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
# This command has JWT and MySQL enabled, Oracle disabled.
CFLAGS=-Wno-error ./configure --add-dynamic-module=../src --prefix=/usr/share/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --http-client-body-temp-path=/var/lib/nginx/tmp/client_body --http-proxy-temp-path=/var/lib/nginx/tmp/proxy --http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi --http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi --http-scgi-temp-path=/var/lib/nginx/tmp/scgi --pid-path=/run/nginx.pid --lock-path=/run/lock/subsys/nginx --user=nginx --group=nginx --with-file-aio --with-ipv6 --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic --with-http_auth_request_module --with-mail=dynamic --with-mail_ssl_module --with-pcre --with-pcre-jit --with-stream=dynamic --with-stream_ssl_module --with-debug --with-cc-opt='-O2 -g -pipe -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS -fexceptions -fstack-protector-strong -grecord-gcc-switches -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -specs=/usr/lib/rpm/redhat/redhat-annobin-cc1 -m64 -mtune=generic -fasynchronous-unwind-tables -fstack-clash-protection -fcf-protection -I /usr/include/libbson-1.0 -I /usr/include/mysql -I/usr/include/libxml2' --with-ld-opt='-Wl,-z,relro -Wl,-z,now -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -Wl,-E -lbson-1.0 -lcurl -ljwt -lmysqlclient -lxml2'

# Build modules only
make modules

# Copy our module to Nginx tree
cp objs/ngx_http_cdn_module.so /usr/lib64/nginx/modules

# Configure Nginx location

# Restrat nginx

# Create empty CDN tree using tools/mkcdn.sh
```


