char *mpfd_get_line(ngx_http_request_t *r, char *begin);
char *mpfd_get_value(ngx_http_request_t *r, char *haystack, char *needle);
char *mpfd_get_header(ngx_http_request_t *r, char *line, char *header);
char *mpfd_get_field(ngx_http_request_t *r, char *rb, bool rb_malloc, char *from, int len);
void upload_cleanup(ngx_http_request_t *r, char *rb, bool rb_malloc, int status);

