/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

/**
 * In-memory cache for 16-byte keys using 128-bit binary tree
 * Usage:
 * // Init cache with max 1 MB RAM
 * cache_t *cache = cache_init(1000000);
 * 
 * // Seek a key (16-byte void*)
 * // If key was found, res->left will have the value (NULL-terminated string); cast it to char*
 * // If key was not found, it was added; store the value by passing the same res and the value (NULL-terminated char*) to cache_put()
 * btree_t *res = cache_seek(cache, key);
 * if (res->left)
 *     printf("%s\n", (char *)res->left);
 * if (! res->left)
 *     cache_put (cache, res, value);
 * 
 * // Destroy cache
 * cache_destroy(cache);
 */

// BTree node structure
typedef struct btree_s btree_t;
struct btree_s {
	btree_t *left;
	btree_t *right;
};

// Cache structure
typedef struct {
	btree_t* root;
	void *list;
	uint64_t list_cnt;
	uint64_t mem_used;
	uint64_t mem_max;
	uint64_t *btree_mask;
} cache_t;

cache_t *cache_init(uint64_t size);
void *cache_seek (cache_t *cache, void *key);
void cache_put (cache_t *cache, btree_t *node, char *value);
void cache_destroy(cache_t *cache);

