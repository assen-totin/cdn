/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

/**
 * In-memory cache for 16-byte keys using 128-bit binary tree
 * Usage:
 * // Init cache with max 1 MB RAM
 * cache_t *cache = cache_init();
 * cache->mem_max = 1000000;
 * 
 * // Seek a key (16-byte void*)
 * // If key was found, node->left will have the value (NULL-terminated string); cast it to char*
 * // If key was not found, it was added; store the value by passing the same node, the key extension and the value (NULL-terminated char*) to cache_put()
 * btree_t *node = cache_seek(cache, key);
 * if (node->left)
 *     printf("%s\n", (char *)node->left);
 * if (! node->left)
 *     cache_put (cache, node, ext, value);
 * 
 * // Destroy cache
 * cache_destroy(cache);
 */

// Prototypes
cache_t *cache_init();
void *cache_seek(cache_t *cache, void *key, int *error);
char *cache_get (cache_t *cache, btree_t *node, char *ext);
void cache_put(cache_t *cache, btree_t *node, char *ext, char *value);
void cache_remove (cache_t *cache, void *key);
void cache_destroy(cache_t *cache);

