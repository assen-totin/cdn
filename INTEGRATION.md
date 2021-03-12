# Concept

The module implements an optimised, custom delivery of authorised content (e.g., user files etc.). Using it is as easy as making a `GET`, `POST` or `DELETE` HTTP request.

The module performs all tasks needed to manage the content: upload, download and delete. You may still implement the uploads and deletions yourself if preferred (e.g. if a custom post-processing of uploaded files like thumbnail generation is required); the CDN may be put in read-only mode in this case.

Each file request must be authorised before served. Authorisation is handled by an external body to which the module connects. The authorisation body should return some file metadata for an approved download.

The business logic for authorisation consists of three main elements:

- Authorisation method: we support JWT, session ID  and transparent (completely offloaded ro external app/service)
- Request type: specifies the format of the request that will be sent to the external authorisation body; we support SQL, JSON, XML and Mongo.
- Transport type: specifies how to connect to the external authorisation body; we support MySQL, PostgreSQL, Oracle, Mongo, Redis, HTTP, TCP and Unix domain socket plus an extra one called Internal.

# Authorisation method

Authorisation token may be supplied in:

- Authorization header, as `Bearer <token>` (default)
- In custom header: set its name in CDN configuration
- In a cookie: set its name in CDN configuration

The authorisation method determines how this authentication token will be processed to extract the actual authorisation token, which is then passed to the authorisation backend. 

You may also use tarnsparent authorisation when we pass all incoming headers and cookies to the authorisation body without working on them.

## Authorisation by JWT

In this case the authorisation token is a JWT, which is extracted and validated to obtain the authorisation value.

The JWT signature verification key must be available to the CDN.

The JWT payload field to use for authorisation must be configured.

The JWT must have a claim named `exp`, containing the Unix timestamp for the expiration time of the token.

## Authorisation by session ID

In this case the authorisation token is a session ID, which used as authorisation value. As the session ID has no digital signature nor expiration time, its validity should be verified by the authorisation body; this means authorisation by session ID is only useful with transparent authorisation.

## Transparent authorisation

This method allows you to send some extra info to the authorisation body. This extra info may be:

- All HTTP headers
- All cookies

This method will automatically include in the request the authorisation value.

This method may be used with some complex request types like `json` or `xml`. It is not applicable for SQL or Mongo request type.

## Authorisation value filters

If the authorisation value needs processing, you may configure a built-in filter to be applied to it. 

The following filters are currently defined:

- `filter_token`: splits the authorisation value by a single-byte delimiter and returns the N-th token. If delimiter is not found, the authorisation value is retained as-is. If the delimiter is found, but not as many time as requested in token count, the authorisation value is reset to NULL, which will deny the request.

# Request types

## Common parameters

The following parameter names are used throughout this document (both for requests and responses):

- `http_method`: string, the name of the HTTP method used like `POST`, `GET`, `DELETE`. Uses capital letters.
- `auth_value`: string, the authentication value (e.g., user ID) extracted from the authorisation token, if any
- `file_id`: string, the ID for the file that is being uploaded, downloaded or deleted
- `filename`: string, the original filename; default is `file`
- `content_type`: string, content type for the file; default is `application/octet-stream`
- `content_disposition`: string, content disposition; if set to `attachment`, the file will be served as attachment; default is to serve inline.
- `etag`: string, the Rtag for the file; default is `00000000000000000000000000000000`
- `status`: int, HTTP-style code; use `200` or `304` to approve request, `403` to deny it, `500` to denote processing error
- `error`: string, will be logged by Nginx if the `status` code indicates an error

## SQL (MySQL, PostgreSQL, Oracle)

Used only with transport of the same kind.

NB: for complex SQL queries, create instead a stored procedure and use stanza like `CALL my_procedure(...)`.

### Upload

Define the SQL INSERT query. It must have placeholders which will be filled with the following values in the given order: `auth_value`, `file`, `filename`, `content_type`, `content_disposition`, `etag`. All these placeholders should be `'%s'` (for strings); don't forget the single quotes around the string placeholder.

### Update

Uses the same configuration as for the upload.

Make sure the file ID is a UNIQUE key in the database and use REPLACE in the `cdn_sql_insert` statement so that the metadata may get updated. 

### Download

Define the SQL SELECT query. It must have two `%s` placeholders - the first will be filled with the file ID and the second - with the value, extracted from the JWT payload.

The SQL query should return a single row with column names matching the keys described above if the request is authorised and no rows if request is declined.

NB: Oracle returns the column names in caps. This is OK.

### Delete

Define the SQL DELETE query. It must have a single `%s` placeholder, which will be filled with the file ID.

## MongoDB

Used only with transport type Mongo.

Database name and collection name are configurable.

Because MongoDB does not allow for textual queries, both file metadata and authorisation data must reside in a single collection with one document per file.

### Upload

The CDN will create a document with the same properties as given above, including the `file_id`, containing the ID of the file to be served by the CDN and `auth_value`, containing the value that will be used by the CDN to authorise access to the file (e.g., user ID or group ID etc.). 

### Update

Same as with the upload. An existing document will be updated.

### Download

The CDN will compose a Mongo query with a filter that will have both properties `file_id` and `auth_value` set: `{file_id: 1234-567-89, auth_value: abcd-efgh-ijkl}`; there should either be one exact match (if access is authorised) or no match.

### Delete

The CDN will compose and execute the same query as with download. The document, if found, will be deleted.

## JSON

This request type can be used with transport type Unix socket, TCP socket HTTP request.

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

### Delete

The request will be the same as with upload, but the `http_method` will be set to PUT.

The response should be the same as with upload.

### Download 

*Request format*

Field `headers` is only included if configured.

Field `cookies` is only included if configured.

The field `auth_value` from authentication token is included if available.

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
### Delete

The authorisation request will be the same as with download, but the `http_method` will be set to DELETE.

The response should be the same as with upload.

## XML

This request type can be used with transport type Unix socket, TCP socket HTTP request.

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

### Delete

The request will be the same as with upload, but the `http_method` will be set to PUT.

The response should be the same as with upload.

### Download

*Request format*

Element `headers` is only included if configured.

Element `cookies` is only included if configured.

The element `auth_value` from authentication token is included only if available.

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

### Delete

The authorisation request will be the same as with download, but the `http_method` will be set to DELETE.

The response should be the same as with upload (only status code, but mandatory).

# Transport types

## Unix socket

This transport is used when request type is `json` (JSON exchange) or `xml` (XML exchange).

The Unix socket must be of type `stream`. The module will half-close the connection once it has written its request and will then expect the response, followed by full connection close by the authorisation body. 

## TCP socket

This transport is used when request type is `json` (JSON exchange) or `xml` (XML exchange).

The module will half-close the connection once it has written its request and will then expect the response, followed by full connection close by the authorisation body. 

NB: TCP is naturally slower than Unix domain socket.

## HTTP

This transport is used when request type is `json` (JSON exchange) or `xml` (XML excahnge).

The URL must be configured. Both HTTP and HTTPS (with official or self-signed certificate) are supported. Authentication to this URL is currently unsupported.

The HTTP request will always be of type POST.

NB: HTTP is naturally slower than both Unix domain socket an TCP socket.

## Redis

This transport is usually used when request type is `json` (JSON file format, preferred) or `xml` (XML file format).

The metadata will be saved into a Redis instance as either JSON (preferred as it is faster) or XML.

## Internal

This transport is usually used when request type is `json` (JSON file format, preferred) or `xml` (XML file format).

The metadata will be saved into a local file alongside the uploaded file itself, as either JSON (preferred as it is faster) or XML.

## MySQL

This transport is only used when request type is set to `mysql`.

## PostgreSQL

This transport is only used when request type is set to `postgresql`.

## Oracle

This transport is only used when request type is set to `oracle`.

## MongoDB

This transport is only used when request type is set to `mongo`.

# File upload

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

# File download

To get a file from the CDN, issue a `GET` HTTP request to the CDN endpoint, followed by the file ID, e.g. `http://cdn.example.com/some-file-id`. The request must be accompanied by an authorisation token as per the chosen configuration (e.g., signed JWT with proper authorisation value and `exp` claim in the `Bearer` field of the `Authorization` header).

# File deletion

To delete a file from the filesystem, issue the same request as for downloading the file, but use DELETE HTTP method.

NB: The metadata for the file will be deleted when using internal authorisation, SQL authorisation or MongoDB. In all other cases the authorisation body should delete the metadata (the `http_method` in the authorisation request will be set to `DELETE`).

# Examples

## Upload a file from command-line
`curl -X POST -F n=test.jpg -F ct='image/jpeg' -F d=@test.jpg  http://cdn.example.com`

## Get an uploaded file
`curl -o test-dnld.jpg http://cdn.example.com/438fcf2c4d4eec4d92acc96dcaaa7940`

## Update and upoaded file
`curl -X PUT -F n=test2.jpg -F ct='image/jpeg' -F d=@test2.jpg  http://cdn.example.com/438fcf2c4d4eec4d92acc96dcaaa7940`


