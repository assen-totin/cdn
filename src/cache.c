/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"

// Init BTree mask
static uint64_t *init_btree_mask() {
	int i;
	uint64_t *btree_mask;

	// CACHE_BTREE_DEPTH-bit - as Nx64 bit
	btree_mask = malloc(CACHE_BTREE_DEPTH * CACHE_BTREE_DEPTH);
	for (i=0; i < CACHE_BTREE_DEPTH/2; i++) 
		*(btree_mask + (2 * i) * 8) = 1L << i;

	for (i=CACHE_BTREE_DEPTH/2; i < CACHE_BTREE_DEPTH; i++) 
		*(btree_mask + (2 * i + 1) * 8) = 1L << i;

	return btree_mask;
}

static btree_t *btree_new_node(cache_t *cache) {
	btree_t *new;

	if ((new = malloc(sizeof(btree_t))) == NULL)
		return NULL;

	new->left = NULL;
	new->right = NULL;

	cache->mem_used += sizeof(btree_t);

	return new;
}

cache_t *cache_init() {
	cache_t *cache;

	if ((cache = malloc(sizeof(cache_t))) == NULL)
		return NULL;

	cache->list = NULL;
	cache->list_cnt = 0;

	cache->btree_mask = init_btree_mask();

	cache->mem_used = sizeof(cache_t) + CACHE_BTREE_DEPTH * CACHE_BTREE_DEPTH;
	cache->mem_max = 0;

	if ((cache->root = btree_new_node(cache)) == NULL)
		return NULL;

	return cache;
}

// Drop a payload
static int cache_payload_free(cache_payload_t *payload) {
	int i;
	int bytes = payload->count * sizeof(cache_payload_el_t) + sizeof(cache_payload_t);

	for (i=0; i < payload->count; i++) {
		bytes += strlen(payload->elements[i].ext);
		free(payload->elements[i].ext);

		bytes += strlen(payload->elements[i].data);
		free(payload->elements[i].data);
	}
	free(payload);

	return bytes;
}

// Check if a key btree_matches the mask
static int btree_match(cache_t *cache, void *key, int level) {
	if (level >= CACHE_BTREE_DEPTH/2) {
		// Check higher 64 bits
		if (*((uint64_t *)(key + 8)) & *(cache->btree_mask + (2 * level + 1) * 8))
			return 1;
	}
	else {
		// Check lower 64 bits
		if (*((uint64_t *)key) & *(cache->btree_mask + (2 * level) * 8))
			return 1;
	}

	return NGX_OK;
}

// Remove a path until a fork is found
// NB: This function is invoked recursively!
static void btree_evict(cache_t *cache, void *key, btree_t *node, int level) {
	btree_t *next;
	int bytes;

	// At last level, free payload
	if (level == CACHE_BTREE_DEPTH) {
		if (node->left) {
			bytes = cache_payload_free((cache_payload_t *)node->left);
			node->left = NULL;
			cache->mem_used -= bytes;
		}
		return;
	}

	if (btree_match(cache, key, level))
		// Bit is 1, we need to go right
		next = node->right;
	else
		// Bit is 0, we need to go right
		next = node->left;
	btree_evict(cache, key, next, level + 1);

	if (! next->left && ! next->right) {
		cache->mem_used -= sizeof(btree_t);
		free(next);
		if (next == node->right)
			node->right = NULL;
		else
			node->left = NULL;
	}
}

// Seek a path or create it as we go
void *cache_seek (cache_t *cache, void *key, int *error) {
	int i;
	uint64_t pos;
	btree_t *node = cache->root;
	char *old_key;
	cache_payload_t *payload;

	*error = 0;

	pthread_mutex_lock(&globals->lock_cache);

	for (i=0; i < CACHE_BTREE_DEPTH; i++) {
		if (btree_match(cache, key, i)) {
			// Bit is 1, we need to go right
			if (! node->right)
				node->right = btree_new_node(cache);
			node = node->right;
		}
		else {
			// Bit is 0, we need to go left
			if (! node->left) 
				node->left = btree_new_node(cache);
			node = node->left;
		}

		// Ensure node allocation was successful
		if (! node) {
			pthread_mutex_lock(&globals->lock_cache);
			*error = 1;
			return NULL;
		}
	}

	// Check the LEFT leaf of the last level;
	// It will be either NULL (if key was not found and just created), or pointer to the cached value
	if (! node->left) {
		// Create the payload
		node->left = malloc(sizeof(cache_payload_t));
		cache->mem_used += sizeof(cache_payload_t);
		payload = (cache_payload_t *) node->left;
		payload->count = 0;
		payload->elements = NULL;

		// If the key was not found, add it to the list - but we may need to evict an older key if over memory
		if (cache->mem_used > cache->mem_max) {
			// Slot number for the new key
			pos = cache->list_cnt - 1;

			// Get the oldest key
			old_key = malloc(CACHE_KEY_LEN);
			memcpy(old_key, cache->list, CACHE_KEY_LEN);

			// Shift all keys one position forward
			memmove(cache->list, cache->list + CACHE_KEY_LEN, pos * CACHE_KEY_LEN);

			// Walk the tree backward, removing nodes till we hit a fork
			btree_evict(cache, old_key, cache->root, 0);
			free(old_key);
		}
		else {
			// Create or expand the list and append the last value
			pos = cache->list_cnt;

			if (cache->list)
				cache->list = realloc(cache->list, (cache->list_cnt + 1) * CACHE_KEY_LEN);
			else
				cache->list = malloc(CACHE_KEY_LEN);

			cache->list_cnt ++;

			cache->mem_used += CACHE_KEY_LEN;
		}

		memcpy(cache->list + (pos * CACHE_KEY_LEN), key, CACHE_KEY_LEN);
	}

	pthread_mutex_unlock(&globals->lock_cache);

	return node;
}

// Search for a key and evict it if found
void cache_remove (cache_t *cache, void *key) {
	uint64_t i;

	// Try to find found the key, so now find its position in the list
	for (i=0; i < cache->list_cnt; i++) {
		if (memcmp(cache->list + i * CACHE_KEY_LEN, key, CACHE_KEY_LEN) == 0)
			break;
	}

	// If not found, return
	if (i == cache->list_cnt)
		return;

	// Shift the index to remove the key from it
	pthread_mutex_lock(&globals->lock_cache);
	memmove(cache->list + i * CACHE_KEY_LEN, cache->list + (i+1) * CACHE_KEY_LEN, (cache->list_cnt - i - 1) * CACHE_KEY_LEN);
	cache->mem_used -= CACHE_KEY_LEN;

	// Evict the key from the btree
	btree_evict(cache, key, cache->root, 0);
	pthread_mutex_unlock(&globals->lock_cache);
}

// Get a value from node that was returned by cache_seek()
char *cache_get (cache_t *cache, btree_t *node, char *ext) {
	cache_payload_t *payload;
	int i;

	if (! node->left)
		return NULL;

	payload = (cache_payload_t *) node->left;

	for (i=0; i < payload->count; i++) {
		if (! strcmp(payload->elements[i].ext, ext))
			return payload->elements[i].data;
	}

	return NULL;
}

// Save a value at the top of the tree
void cache_put (cache_t *cache, btree_t *node, char *ext, char *value) {
	cache_payload_t *payload = (cache_payload_t *) node->left;

	if (payload->count) {
		payload->elements = realloc(payload->elements, (payload->count + 1) * sizeof(cache_payload_el_t));
	}
	else {
		payload->elements = malloc(sizeof(cache_payload_el_t));
	}

	payload->elements[payload->count].ext = ext;
	payload->elements[payload->count].data = value;

	payload->count ++;

	cache->mem_used += sizeof(cache_payload_el_t);
	cache->mem_used += strlen(ext);
	cache->mem_used += strlen(value);
}

// Remove all elements from the tree
// NB: This function is invoked recursively!
static void btree_purge(btree_t *node, int level) {
	// At last level, free payload
	if (level == CACHE_BTREE_DEPTH) {
		cache_payload_free((cache_payload_t *) node->left);
		return;
	}

	// Dive further
	if (node->left) {
		btree_purge(node->left, level + 1);
		// Free our next level
		free(node->left);
	}

	if (node->right) {
		btree_purge(node->right, level + 1);
		// Free our next level
		free(node->right);
	}
}

void cache_destroy(cache_t *cache) {
	if (! cache)
		return;

	if (cache->root) {
		btree_purge(cache->root, 0);
		free(cache->root);
	}

	if (cache->btree_mask)
		free(cache->btree_mask);

	if (cache->list)
		free(cache->list);

	free(cache);
}

