/*
 * LTFS directory-sorted read-ahead / prefetch cache (prototype).
 *
 * Opt-in via environment variables:
 *   LTFS_READAHEAD_MB         - total cache cap in MiB (0 or unset = disabled)
 *   LTFS_READAHEAD_FILE_MB    - max individual file size to cache in MiB (default 1)
 *
 * When enabled, a readdir call is treated as a hint that the user is about
 * to walk the directory (grep -r, tar, cp -r, etc.). A background thread
 * snapshots the directory's small files, sorts them by their first extent's
 * tape position, and reads them into an in-memory LRU cache using
 * ltfs_fsraw_read(). Subsequent ltfs_fsops_read() calls that hit the cache
 * are served without touching the tape.
 */

#ifndef __LTFS_READAHEAD_H__
#define __LTFS_READAHEAD_H__

#include <stdbool.h>
#include <sys/types.h>

struct ltfs_volume;
struct dentry;

/*
 * Initialize the readahead subsystem for a volume. Reads env vars to decide
 * whether to enable. Returns 0 on success (even when disabled); a negative
 * error code on failure. If disabled, readahead_initialized() returns false
 * and all the other entry points are no-ops.
 */
int readahead_init(struct ltfs_volume *vol);

/* Shut down and free the cache. Safe to call even if not initialized. */
int readahead_destroy(struct ltfs_volume *vol);

/* True iff the readahead worker is running for this volume. */
bool readahead_initialized(struct ltfs_volume *vol);

/*
 * Hint: a directory was just read. Queue its children for prefetch.
 * Cheap: snapshots under the dir's contents_lock and wakes the worker.
 */
void readahead_hint_dir(struct dentry *dir, struct ltfs_volume *vol);

/*
 * Try to service a read from the cache.
 * Returns:
 *   >= 0  : bytes copied; this read is fully serviced, skip the tape path.
 *   -1    : cache miss; caller should fall through to the normal read path.
 */
ssize_t readahead_try_read(struct dentry *d, char *buf, size_t count,
                           off_t offset, struct ltfs_volume *vol);

/*
 * Drop any cached data for this dentry. Call on write/truncate/unlink.
 */
void readahead_invalidate(struct dentry *d, struct ltfs_volume *vol);

#endif /* __LTFS_READAHEAD_H__ */
