/**
 * Nginx CDN module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"

// Init FS
fs_t *fs_init() {
	fs_t *fs;

	if ((fs = malloc(sizeof(fs_t))) == NULL)
		return NULL;

	fs->server_id = 0;
	fs->depth = 0;
	fs->root = NULL;

	return fs;
}

// Destroy fs
void fs_destroy(fs_t *fs) {
	if (fs->root)
		free(fs->root);

	free(fs);
}

