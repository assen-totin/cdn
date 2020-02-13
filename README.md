Nginx configuration directives:

```
location /abc/xyz
	medicloud;
	mongo_enable true;
	mongo_url mongodb://user:password@host:port;
	mongo_db database_name;
	fs_enable true;
	fs_root /usr/share/curaden/fs;
	fs_depth 4;
	jwt_token ABC...XYZ;
```

To create a blank filesystem storage, copy the tools/mkfs.sh to the top level directory and run it from there; remove it once done.


