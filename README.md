Nginx configuration directives:

```
location /abc/xyz
	medicloud;
	fs_root /usr/share/curaden/fs;
	fs_depth 4;
	auth_socket /path/to/some.sock;
```

To create a blank filesystem storage, copy the tools/mkfs.sh to the top level directory and run it from there; remove it once done.


