# Concept

The module implements an optimised, custom delivery of authorised content (e.g., user files etc.). 

The module only serves files. Their upload must be handled separately; it is quite easy, though - see File Uploads below.

Each file request must be authorised before served. Authorisation is handled by an external body to which the module connects. 

The business logic for authorisation consists of two main elements:

- Request type: specifies the format of the request that will be sent to the external authorisation body.
- Transport type: specifies how to connect to the external authorisation body. 

# Initialise

To create a blank filesystem storage, use `tools/mkcdn.sh`.

# Nginx configuration directives:

```
location /abc/xyz
	cdn;
	cdn_fs_root /usr/share/curaden/fs;		// Root directgory of CDN 
	cdn_fs_depth 4;							// CDN tree depth
	cdn_request_type json;					// Type of authorisation request to perform: "json"
	cdn_transport_type unix;				// Type of transport for authorisation: "unix" 
	cdn_unix_socket /path/to/some.sock;		// Path to the Unix socket
	cdn_jwt_key 0123456789ABCDEF;			// JWT validation key
	cdn_jwt_cookie my_auth_cookie;			// Cookie which contains the JWT
	cdn_jwt_field uid;						// Field in JWT used for authtorisation
	cdn_json_extended no;					// Send extended JSON in request (with headers and cookies)
	cdn_header_auth X-Custom-JWT			// Custom headfer to search for JWT
```

# Usage scenarios and configuration

## Authorisation by JWT

This is the preferred and more common scenario. In this case a JWT is extracted to find the value for an authorisation field, which is then passed to the authorisation backend. 

To use this scenario, set the JWT signature verification key in configuration option `cdn_jwt_key`.

Specify the JWT paylod field to use for authorisation in configuration option `cdn_jwt_field`.

JWT can be supplied in:

- Authorization header, as `Bearer <token>` (default)
- In custom header: set its name in configuration option `cdn_jwt_header`
- In a cookie: set its name in configuration option `cdn_jwt_cookie`

## Offloaded authorisation

In this case selected headers and all cookies are sent to the authorisation body. To have them sent, set the configuration option `cdn_json_extended` to `yes`. 

The three headers that are included if available are `Authorization`, `If-None-Match` and `If-Modified-Since`. Extra header may be specified in configuration option `FIXME` (coming soon). 

This case typically uses JSON request type and Unix socket transport.

# Request types

## JSON

This request type is usually used with transport type set to `unix` (Unix socket).

### Request format

Fields `headers` and `cookies` are only included if configuration option `cdn_json_extended` is set to `yes`. 

The field `jwt_value` from JWT token is included only if configuration options `cdn_jwt_key` and `cdn_jwt_field` are set.

```
{
	"uri" : "/some-file-id",
	"jwt_value" : "12345"
	"headers" : [
		{
			"name": "If-None-Match",
			"value": "00000000000000000000000000000000"
		},
		{
			"name": "If-Modified-Since",
			"value": "Wed, 21 Oct 2015 07:28:00 GMT"
		},
		{
			"name": "Authorization",
			"value": "Bearer abcdefgh123456"
		}
	],
	"cookies": [
		{
			"name": "some_cookie_name",
			"value": "some_cookie_value"
		},
		{
			"name": "other_cookie_name",
			"value": "other_cookie_value"
		}
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

## SQL

Set the SQL query to run in the configuration option `cnd_sql_query`. Use `%s` as placeholder for the value, extracted from the JWT payload.

The SQL query should return a single row with column names matching the keys in the JSON response above.

Hint: for complex queries, create a stored procedure and use stanza like `CALL my_procedure(%s)`.

# Transport types

## Unix socket

Set the path to the Unix socket in configuration option `cdn_unix_socket`. Note that socket must be writable by the Nginx user. 

This transport is usually used whet request type is `json` (JSON exchange).

The Unix socket must be of type `stream`. The module will half-close the connection once it has written its JSON and will then expect the response JSON, followed by full connection close by the authorisation body. 

## MySQL

Set the DSN in the configuration option `cnd_sql_dsn` using the following syntax: `host:port:username:password:database`. If you host is `localhost`, you may put the full path to the Unix socket instead of port number.

# Dev environment setup

NB: This is for RHEL-8 and derivatives. RHEL-7 has some differences in packages and in the configure command. 

```
# Go to checkout dir

# Install build deps
yum groupinstall -y 'Development Tools'
yum install -y nginx libbson-devel libcurl-devel pcre-devel libxml2-devel libxml-devel libxslt-devel gd-devel mariadb-connector-c-devel perl-ExtUtils-Embed

# Install libjwt from https://github.com/benmcollins/libjwt

# Copy our module config
cp support-files/nginx/modules/* /usr/share/nginx/modules

# Get the Nginx sources (version must match the installed one from RPM)
wget http://nginx.org/download/nginx-1.14.1.tar.gz
gunzip nginx-1.14.1.tar.gz
tar xf nginx-1.14.1.tar
cd nginx-1.14.1

# Configure the build the same way as the RPM packages does
CFLAGS=-Wno-error ./configure --add-dynamic-module=../src --prefix=/usr/share/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --http-client-body-temp-path=/var/lib/nginx/tmp/client_body --http-proxy-temp-path=/var/lib/nginx/tmp/proxy --http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi --http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi --http-scgi-temp-path=/var/lib/nginx/tmp/scgi --pid-path=/run/nginx.pid --lock-path=/run/lock/subsys/nginx --user=nginx --group=nginx --with-file-aio --with-ipv6 --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic --with-http_auth_request_module --with-mail=dynamic --with-mail_ssl_module --with-pcre --with-pcre-jit --with-stream=dynamic --with-stream_ssl_module --with-debug --with-cc-opt='-O2 -g -pipe -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS -fexceptions -fstack-protector-strong -grecord-gcc-switches -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -specs=/usr/lib/rpm/redhat/redhat-annobin-cc1 -m64 -mtune=generic -fasynchronous-unwind-tables -fstack-clash-protection -fcf-protection -I /usr/include/libbson-1.0' --with-ld-opt='-Wl,-z,relro -Wl,-z,now -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -Wl,-E -lbson-1.0 -lcurl -ljwt'

# Build modules only
make modules

# Copy our module to Nginx tree
cp objs/ngx_http_cdn_module.so /usr/lib64/nginx/modules

# Configure Nginx location

# Restrat nginx

# Create empty CDN tree using tools/mkcdn.sh
```
# File uploads

Here is the workflow to upload a file to the CDN:

## Create file ID

- Use a lightweight hashing algorithm. 
- We recommend strongly 128-bit murmur3: very fast, very sensitive, very good distribution, open source.
- Ensure input is unique: use the file name, the current timestamp (with at least ms precision), the ID (or session ID) of the user and an ID of the app instance (e.g., IP address).
- Convert the ID to lowercase hex string.
- Do not use random data: low entropy on virtualised systems will slow you down.

## Write the file ID and its metadata

Write them to the metadata storage which will be used by CDN for authorisation (e.g., to the MySQL database).

- Original file name. Will be used when serving the file with `Attachment` disposition. 
- Upload timestamp. Will be compared to `If-Modified-Since` request header.
- Etag: will be used for `Etag` response header and compared to `If-None-Match` request header.
- MIME type. Will be used as `Content-Type`.
- Content disposition – serve inline or as attachment.
- Size: file size in bytes.

Test your authorisation query to make sure metadata is properly returned.

## Write the file into CDN file structure

- Read the first N letters of the file ID generated above (where N is the depth of the CDN tree).
- Use each of these N letters as one directory level.
- Place the file in the resulting path.
- Example: with depth of 4, file ID `abcdef0123456789` must be placed at path `/a/b/c/d/abcdef0123456789` inside the CDN root (note that the first N letters are *not* removed form the file name, they just for the path - this is how path will be determined when the CDN needs to serve the file).

