/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

/**
 * Index of changes for faster mirroring
 * 
 * Saved as a regular file inside the CDN. One file for each hour in UTC. May be missing. File name: <prefix>YYYYMMDDHH
 * Usage:
 * index_t *index = index_init();
 * 
 * // Destroy index
 * index_destroy(index);
 */

// Prototypes
index_t *index_init();
ngx_int_t index_open (session_t *session);
ngx_int_t index_write (session_t *session, int action, char *filename);
void index_destroy(index_t *index);

