# Concept

The module implements an optimised, custom delivery of authorised content (e.g., user files etc.). 

The module only serves files. Their upload must be handled separately; it is quite easy, though - see UPLOAD.md

Each file request must be authorised before served. Authorisation is handled by an external body to which the module connects. 

The business logic for authorisation consists of two main elements:

- Request type: specifies the format of the request that will be sent to the external authorisation body.
- Transport type: specifies how ot connect to the external authorisation body. 

# Initialise

To create a blank filesystem storage, use tools/mkcdn.sh.

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

This is the prefererred and more common scenario. In this case a JWT is extracted to find the value for an authorisation field, which is then passed to the authorisation backend. 

To use this scenario, set the JWT signature verification key in configuration option "cdn_jwt_key".

Specify the JWT paylod field to use for authorisation in configuration option "cdn_jwt_field".

JWT can be supplied in:

- Authorization header, as Bearer (default)
- In custom header: set its name in configuration otion "cdn_jwt_header"
- In a cookie: set its name in configuration option "cdn_jwt_cookie"

## Offloaded authorisation

In this case selected headers and all cookies are sent to the authorisation body. To have them sent, set the configuration option "cdn_json_extended" to "yes". 

The three headers that are included if available are Authorization, If-None-Match and If-Modified-Since. Extra header may be specfified in configuration option "FIXME". 

This case typically uses JSON request type and Unix socket transport.

# Request types

## JSON

This request type is usually used with transport type set to "unix" (Unix socket).

### Request format

Fields "headers" and "cookies" are only included if configuration option "cdn_json_extended" is set to "yes". 

The field "jwt_value" from JWT token is included only if configuration options "cdn_jwt_key" and "cdn_jwt_field" are set.

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
	"file": string, mandatory, the CDN file name (path is not needed as it is inclided in the filename)
	"status": int, optional, http code; use 200, 304, 404, 500; if missing, file will be served if found (unless 304 can be returned), else 404
	"filename": string, optional, the file name to give the user; the value of "file" will be used if missing
	"content_type": string, optional, "application/octet-stream" will be used if missing
	"content_dispostion": string, optional, if set to "attachment" or missing, "attachment wil be used"; any other value will unset Content-Disposition
	"etag": string, optional, "00000000000000000000000000000000" will be used if missing
	"length": int, optional, stat() wil be used if missing
	"upload_date": int, optional, Unix timestamp of mtime; stat() wil be used if missing
	"error"	: string, optional, will be logged by Nginx
}
```

## SQL

Set the SQL query to run in the configuration option "cnd_sql_query". Use "%s" as placeholder for the value, extracted from the JWT payload.

Hint: for complex queris, create a stored procedure and use stanza like "CALL my_procedure(%s)".

# Transport types

## Unix socket

Set the path to the Unix socket in configuratin option "cdn_unix_socket". Note that socket must be writable by the Nginx user. 

This transport is usually used whet request type is "json" (JSON exchange).

The Unix socket must be of type "stream". The module will half-close the connection once it has written its JSON and will then expect the response JSON, followed by full connection close by the authorisation body. 

## SQL

Set the actual SQL connection engine to use in configuration option "cnd_sql_dsn" (default is "mysql").

Set the DSN in the configuration option "cnd_sql_dsn". 

# Dev environment setup

```
# Go to checkout dir

# Install build deps
yum groupinstall -y 'Development Tools'
yum install -y nginx libbson-devel libcurl-devel pcre-devel libxml2-devel libxml-devel libxslt-devel gd-devel perl-ExtUtils-Embed

# Install libjwt from https://github.com/benmcollins/libjwt

# Copy our module config
cp support-files/nginx/modules/* /usr/share/nginx/modules

# Get the Nginx sources (version must match the installed one from RPM)
wget http://nginx.org/download/nginx-1.14.1.tar.gz
gunzip nginx-1.14.1.tar.gz
tar xf nginx-1.14.1.tar
cd nginx-1.14.1

# Configure the build
CFLAGS=-Wno-error ./configure --add-dynamic-module=../src --prefix=/usr/share/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --http-client-body-temp-path=/var/lib/nginx/tmp/client_body --http-proxy-temp-path=/var/lib/nginx/tmp/proxy --http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi --http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi --http-scgi-temp-path=/var/lib/nginx/tmp/scgi --pid-path=/run/nginx.pid --lock-path=/run/lock/subsys/nginx --user=nginx --group=nginx --with-file-aio --with-ipv6 --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic --with-http_auth_request_module --with-mail=dynamic --with-mail_ssl_module --with-pcre --with-pcre-jit --with-stream=dynamic --with-stream_ssl_module --with-debug --with-cc-opt='-O2 -g -pipe -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS -fexceptions -fstack-protector-strong -grecord-gcc-switches -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -specs=/usr/lib/rpm/redhat/redhat-annobin-cc1 -m64 -mtune=generic -fasynchronous-unwind-tables -fstack-clash-protection -fcf-protection -I /usr/include/libbson-1.0' --with-ld-opt='-Wl,-z,relro -Wl,-z,now -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -Wl,-E -lbson-1.0 -lcurl -ljwt'

# Build modules only
make modules

# Copy our module to Nginx tree
cp objs/ngx_http_cdn_module.so /usr/lib64/nginx/modules

# Configure Nginx location

# Restrat nginx

# Create empty CDN tree using tools/mkfs.sh
```


