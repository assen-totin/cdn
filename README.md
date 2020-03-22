Nginx configuration directives:

```
location /abc/xyz
	medicloud;
	fs_root /usr/share/curaden/fs;
	fs_depth 4;
	auth_socket /path/to/some.sock;
```

To create a blank filesystem storage, copy the tools/mkfs.sh to the top level directory and run it from there; remove it once done.

Unix socket protocol:

Request: (all members of "headers" and "cookies" are optional)

```
{
	"uri" : "/test123/lala",
	"headers" : {
		"if_none_match": "00000000000000000000000000000000", // eTag
		"if_modified_since": 1234567890,	// Unix timestamp of the header value
		"authorisation": "Bearer abcdefgh123456",
	},
	"cookies" : {
		"some_cookie_name": "some_cookie_value",
		"other_cookie_name": "other_cookie_value"
	}
}
```

Response

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

