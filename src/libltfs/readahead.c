/*
 * LTFS directory-sorted read-ahead / prefetch cache (prototype).
 *
 * See readahead.h for the public interface and enablement env vars.
 *
 * Design notes:
 *   - The cache is a uthash-based map of dentry UID -> file-data buffer,
 *     with a doubly-linked LRU list and a byte budget.
 *   - Only files whose total size is <= LTFS_READAHEAD_FILE_MB are candidates.
 *   - readdir acts as a hint. We snapshot the dir's children under the
 *     parent's contents_lock, bump numhandles on each candidate, peek at
 *     the first-extent tape position for a sort key, release locks, and
 *     push the batch to the worker thread.
 *   - The worker sorts by (partition, block), then for each item inserts a
 *     "pending" placeholder in the cache, calls ltfs_fsraw_read() to populate
 *     the buffer in tape-sorted order, then re-acquires the cache mutex to
 *     either promote the placeholder to a ready entry or (if it was removed
 *     by readahead_invalidate() in the meantime) discard the buffer.
 *   - Any write/truncate/unlink call should invalidate the entry. That makes
 *     the "stale cache after write" race safe: the placeholder is removed
 *     before the write completes, and the worker's late insert is discarded.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include "ltfs.h"
#include "ltfs_fsops.h"
#include "ltfs_fsops_raw.h"
#include "fs.h"
#include "readahead.h"

#define RA_DEFAULT_FILE_MAX_MB   (1)     /* default per-file cap (MiB) */

struct ra_cache_entry {
	uint64_t                uid;        /* dentry UID (hash key) */
	uint64_t                size;       /* cached bytes */
	char                   *data;       /* heap buffer (NULL while pending) */
	bool                    pending;    /* true while worker is reading */
	struct ra_cache_entry  *lru_prev;
	struct ra_cache_entry  *lru_next;
	UT_hash_handle          hh;
};

struct ra_work_item {
	struct dentry *d;                   /* numhandles pre-bumped */
	uint64_t       sort_key;            /* (partition << 48) | block */
	uint64_t       size;                /* snapshot of d->size at hint time */
};

struct ra_work {
	struct ra_work_item *items;
	size_t               count;
	struct ra_work      *next;
};

struct readahead_data {
	struct ltfs_volume      *vol;

	/* worker */
	ltfs_thread_t            thread_id;
	ltfs_thread_mutex_t      queue_mutex;
	ltfs_thread_cond_t       queue_cond;
	bool                     keepalive;
	bool                     thread_running;

	/* pending prefetch work */
	struct ra_work          *work_head;
	struct ra_work          *work_tail;

	/* cache */
	ltfs_thread_mutex_t      cache_mutex;
	struct ra_cache_entry   *cache_hash;
	struct ra_cache_entry   *lru_head;     /* most recent */
	struct ra_cache_entry   *lru_tail;     /* least recent (evict from here) */
	uint64_t                 cache_bytes;

	/* tunables */
	uint64_t                 cache_max_bytes;
	uint64_t                 file_size_max;

	/* stats */
	uint64_t                 hits;
	uint64_t                 misses;
	uint64_t                 prefetched_files;
	uint64_t                 prefetched_bytes;
	uint64_t                 invalidations;
	uint64_t                 evictions;
};

/* ------------------------------------------------------------------ */
/* LRU helpers. Caller must hold cache_mutex. */

static void lru_remove(struct readahead_data *priv, struct ra_cache_entry *e)
{
	if (e->lru_prev)
		e->lru_prev->lru_next = e->lru_next;
	else
		priv->lru_head = e->lru_next;

	if (e->lru_next)
		e->lru_next->lru_prev = e->lru_prev;
	else
		priv->lru_tail = e->lru_prev;

	e->lru_prev = e->lru_next = NULL;
}

static void lru_push_head(struct readahead_data *priv, struct ra_cache_entry *e)
{
	e->lru_prev = NULL;
	e->lru_next = priv->lru_head;
	if (priv->lru_head)
		priv->lru_head->lru_prev = e;
	priv->lru_head = e;
	if (! priv->lru_tail)
		priv->lru_tail = e;
}

static void lru_touch(struct readahead_data *priv, struct ra_cache_entry *e)
{
	if (priv->lru_head == e)
		return;
	lru_remove(priv, e);
	lru_push_head(priv, e);
}

/* Evict entries from the LRU tail until there's room for 'need' bytes
 * (or the cache is empty). Pending entries are skipped — they'll be
 * accounted when they become ready. Caller holds cache_mutex. */
static void evict_until_fits(struct readahead_data *priv, uint64_t need)
{
	struct ra_cache_entry *e, *prev;

	if (need > priv->cache_max_bytes)
		return;

	e = priv->lru_tail;
	while (e && priv->cache_bytes + need > priv->cache_max_bytes) {
		prev = e->lru_prev;
		if (e->pending) {
			/* Can't evict a pending entry; skip it. */
			e = prev;
			continue;
		}
		HASH_DEL(priv->cache_hash, e);
		lru_remove(priv, e);
		priv->cache_bytes -= e->size;
		priv->evictions++;
		free(e->data);
		free(e);
		e = prev;
	}
}

/* ------------------------------------------------------------------ */
/* Worker */

static int cmp_work_item(const void *a, const void *b)
{
	const struct ra_work_item *ia = a;
	const struct ra_work_item *ib = b;
	if (ia->sort_key < ib->sort_key) return -1;
	if (ia->sort_key > ib->sort_key) return  1;
	return 0;
}

/* Release a work_item: drop the numhandles reference we took at hint time. */
static void release_item(struct ra_work_item *it)
{
	if (it->d)
		fs_release_dentry(it->d);
}

/* Process one batch of items (already sorted). The cache mutex must NOT
 * be held here; this function acquires it internally as needed. */
static void process_batch(struct readahead_data *priv, struct ra_work *w)
{
	size_t i;
	struct ra_cache_entry *placeholder, *existing;
	uint64_t key;
	ssize_t nread;
	char *buf;

	qsort(w->items, w->count, sizeof(w->items[0]), cmp_work_item);

	for (i = 0; i < w->count; i++) {
		struct ra_work_item *it = &w->items[i];
		struct dentry *d = it->d;
		uint64_t want_size;

		/* Bail early if we're shutting down. */
		ltfs_thread_mutex_lock(&priv->queue_mutex);
		if (! priv->keepalive) {
			ltfs_thread_mutex_unlock(&priv->queue_mutex);
			/* Release remaining items and return. */
			for (; i < w->count; i++)
				release_item(&w->items[i]);
			return;
		}
		ltfs_thread_mutex_unlock(&priv->queue_mutex);

		/* Skip files that got dirty or deleted after the hint snapshot. */
		acquireread_mrsw(&d->meta_lock);
		if (d->deleted || d->dirty || d->isdir || d->isslink ||
		    d->size == 0 || d->size > priv->file_size_max) {
			releaseread_mrsw(&d->meta_lock);
			release_item(it);
			it->d = NULL;
			continue;
		}
		want_size = d->size;
		releaseread_mrsw(&d->meta_lock);

		if (want_size != it->size) {
			/* Size changed since hint; skip to be safe. */
			release_item(it);
			it->d = NULL;
			continue;
		}

		/* Insert a pending placeholder, making room first. */
		key = d->uid;
		ltfs_thread_mutex_lock(&priv->cache_mutex);
		HASH_FIND(hh, priv->cache_hash, &key, sizeof(key), existing);
		if (existing) {
			/* Already present or being fetched by someone else. Skip. */
			ltfs_thread_mutex_unlock(&priv->cache_mutex);
			release_item(it);
			it->d = NULL;
			continue;
		}
		evict_until_fits(priv, want_size);
		if (priv->cache_bytes + want_size > priv->cache_max_bytes) {
			/* Still no room (all remaining entries are pending); skip. */
			ltfs_thread_mutex_unlock(&priv->cache_mutex);
			release_item(it);
			it->d = NULL;
			continue;
		}
		placeholder = calloc(1, sizeof(*placeholder));
		if (! placeholder) {
			ltfs_thread_mutex_unlock(&priv->cache_mutex);
			release_item(it);
			it->d = NULL;
			continue;
		}
		placeholder->uid = key;
		placeholder->size = want_size;
		placeholder->pending = true;
		HASH_ADD(hh, priv->cache_hash, uid, sizeof(key), placeholder);
		lru_push_head(priv, placeholder);
		priv->cache_bytes += want_size;
		ltfs_thread_mutex_unlock(&priv->cache_mutex);

		/* Read in tape-sorted order. */
		buf = malloc(want_size);
		if (! buf) {
			nread = -1;
		} else {
			nread = ltfs_fsraw_read(d, buf, want_size, 0, priv->vol);
		}

		/* Commit or discard. */
		ltfs_thread_mutex_lock(&priv->cache_mutex);
		HASH_FIND(hh, priv->cache_hash, &key, sizeof(key), existing);
		if (existing == placeholder && nread == (ssize_t)want_size) {
			placeholder->data = buf;
			placeholder->pending = false;
			priv->prefetched_files++;
			priv->prefetched_bytes += want_size;
			buf = NULL;
		} else if (existing == placeholder) {
			/* Read failed or short; remove placeholder. */
			HASH_DEL(priv->cache_hash, placeholder);
			lru_remove(priv, placeholder);
			priv->cache_bytes -= placeholder->size;
			free(placeholder);
		} else {
			/* Placeholder was invalidated out from under us. Just drop buf. */
		}
		ltfs_thread_mutex_unlock(&priv->cache_mutex);
		free(buf);

		release_item(it);
		it->d = NULL;
	}
}

static ltfs_thread_return readahead_thread(void *data)
{
	struct readahead_data *priv = data;
	struct ra_work *w;

	for (;;) {
		ltfs_thread_mutex_lock(&priv->queue_mutex);
		while (priv->keepalive && ! priv->work_head)
			ltfs_thread_cond_wait(&priv->queue_cond, &priv->queue_mutex);
		if (! priv->keepalive && ! priv->work_head) {
			ltfs_thread_mutex_unlock(&priv->queue_mutex);
			break;
		}
		w = priv->work_head;
		priv->work_head = w->next;
		if (! priv->work_head)
			priv->work_tail = NULL;
		ltfs_thread_mutex_unlock(&priv->queue_mutex);

		process_batch(priv, w);
		free(w->items);
		free(w);
	}

	ltfs_thread_exit();
	return LTFS_THREAD_RC_NULL;
}

/* ------------------------------------------------------------------ */
/* Public entry points */

bool readahead_initialized(struct ltfs_volume *vol)
{
	return vol && vol->readahead_handle != NULL;
}

int readahead_init(struct ltfs_volume *vol)
{
	const char *env_mb, *env_file_mb;
	unsigned long cache_mb, file_mb;
	struct readahead_data *priv;
	int ret;

	if (! vol)
		return -LTFS_NULL_ARG;

	env_mb = getenv("LTFS_READAHEAD_MB");
	if (! env_mb || ! *env_mb)
		return 0;  /* disabled */
	cache_mb = strtoul(env_mb, NULL, 10);
	if (cache_mb == 0)
		return 0;  /* disabled */

	env_file_mb = getenv("LTFS_READAHEAD_FILE_MB");
	if (env_file_mb && *env_file_mb)
		file_mb = strtoul(env_file_mb, NULL, 10);
	else
		file_mb = RA_DEFAULT_FILE_MAX_MB;
	if (file_mb == 0)
		file_mb = RA_DEFAULT_FILE_MAX_MB;

	priv = calloc(1, sizeof(*priv));
	if (! priv)
		return -LTFS_NO_MEMORY;
	priv->vol = vol;
	priv->cache_max_bytes = (uint64_t)cache_mb * 1024ULL * 1024ULL;
	priv->file_size_max   = (uint64_t)file_mb  * 1024ULL * 1024ULL;
	priv->keepalive = true;

	ret = ltfs_thread_mutex_init(&priv->queue_mutex);
	if (ret)
		goto err_free;
	ret = ltfs_thread_cond_init(&priv->queue_cond);
	if (ret)
		goto err_qmutex;
	ret = ltfs_thread_mutex_init(&priv->cache_mutex);
	if (ret)
		goto err_cond;
	ret = ltfs_thread_create(&priv->thread_id, readahead_thread, priv);
	if (ret)
		goto err_cmutex;

	priv->thread_running = true;
	vol->readahead_handle = priv;

	fprintf(stderr,
	        "LTFS readahead: enabled, cache=%" PRIu64 " MiB, file_max=%" PRIu64 " MiB\n",
	        priv->cache_max_bytes >> 20, priv->file_size_max >> 20);
	return 0;

err_cmutex:
	ltfs_thread_mutex_destroy(&priv->cache_mutex);
err_cond:
	ltfs_thread_cond_destroy(&priv->queue_cond);
err_qmutex:
	ltfs_thread_mutex_destroy(&priv->queue_mutex);
err_free:
	free(priv);
	return ret > 0 ? -ret : ret;
}

int readahead_destroy(struct ltfs_volume *vol)
{
	struct readahead_data *priv;
	struct ra_work *w, *wnext;
	struct ra_cache_entry *e, *etmp;
	size_t i;

	if (! vol || ! vol->readahead_handle)
		return 0;
	priv = vol->readahead_handle;
	vol->readahead_handle = NULL;

	/* Signal worker to stop and wait for it. */
	ltfs_thread_mutex_lock(&priv->queue_mutex);
	priv->keepalive = false;
	ltfs_thread_cond_broadcast(&priv->queue_cond);
	ltfs_thread_mutex_unlock(&priv->queue_mutex);
	if (priv->thread_running)
		ltfs_thread_join(priv->thread_id);

	/* Drain any remaining queued work. */
	w = priv->work_head;
	while (w) {
		wnext = w->next;
		for (i = 0; i < w->count; i++)
			release_item(&w->items[i]);
		free(w->items);
		free(w);
		w = wnext;
	}

	/* Free cache. */
	HASH_ITER(hh, priv->cache_hash, e, etmp) {
		HASH_DEL(priv->cache_hash, e);
		free(e->data);
		free(e);
	}

	fprintf(stderr,
	        "LTFS readahead: hits=%" PRIu64 " misses=%" PRIu64
	        " prefetched=%" PRIu64 " files (%" PRIu64 " MiB)"
	        " invalidated=%" PRIu64 " evicted=%" PRIu64 "\n",
	        priv->hits, priv->misses,
	        priv->prefetched_files, priv->prefetched_bytes >> 20,
	        priv->invalidations, priv->evictions);

	ltfs_thread_mutex_destroy(&priv->cache_mutex);
	ltfs_thread_cond_destroy(&priv->queue_cond);
	ltfs_thread_mutex_destroy(&priv->queue_mutex);
	free(priv);
	return 0;
}

ssize_t readahead_try_read(struct dentry *d, char *buf, size_t count,
                           off_t offset, struct ltfs_volume *vol)
{
	struct readahead_data *priv;
	struct ra_cache_entry *e;
	uint64_t key;
	ssize_t n;

	if (! vol || ! vol->readahead_handle || ! d || ! buf)
		return -1;
	priv = vol->readahead_handle;
	key = d->uid;

	ltfs_thread_mutex_lock(&priv->cache_mutex);
	HASH_FIND(hh, priv->cache_hash, &key, sizeof(key), e);
	if (! e || e->pending || ! e->data) {
		priv->misses++;
		ltfs_thread_mutex_unlock(&priv->cache_mutex);
		return -1;
	}
	lru_touch(priv, e);

	if ((uint64_t)offset >= e->size) {
		n = 0;
	} else {
		uint64_t avail = e->size - (uint64_t)offset;
		n = (count < avail) ? (ssize_t)count : (ssize_t)avail;
		memcpy(buf, e->data + offset, (size_t)n);
	}
	priv->hits++;
	ltfs_thread_mutex_unlock(&priv->cache_mutex);
	return n;
}

void readahead_invalidate(struct dentry *d, struct ltfs_volume *vol)
{
	struct readahead_data *priv;
	struct ra_cache_entry *e;
	uint64_t key;

	if (! vol || ! vol->readahead_handle || ! d)
		return;
	priv = vol->readahead_handle;
	key = d->uid;

	ltfs_thread_mutex_lock(&priv->cache_mutex);
	HASH_FIND(hh, priv->cache_hash, &key, sizeof(key), e);
	if (e) {
		HASH_DEL(priv->cache_hash, e);
		lru_remove(priv, e);
		priv->cache_bytes -= e->size;
		priv->invalidations++;
		if (! e->pending)
			free(e->data);
		/* If pending, the worker will discover the entry is gone and drop
		 * its just-read buffer. Either way we free the entry here. */
		free(e);
	}
	ltfs_thread_mutex_unlock(&priv->cache_mutex);
}

/* ------------------------------------------------------------------ */
/* Hint path: snapshot a directory's children and enqueue for prefetch. */

void readahead_hint_dir(struct dentry *dir, struct ltfs_volume *vol)
{
	struct readahead_data *priv;
	struct name_list *entry, *tmp;
	struct ra_work_item *items = NULL;
	size_t capacity = 0, count = 0;
	struct ra_work *work;

	if (! vol || ! vol->readahead_handle || ! dir || ! dir->isdir)
		return;
	priv = vol->readahead_handle;

	acquireread_mrsw(&dir->contents_lock);
	if (HASH_COUNT(dir->child_list) == 0) {
		releaseread_mrsw(&dir->contents_lock);
		return;
	}

	HASH_ITER(hh, dir->child_list, entry, tmp) {
		struct dentry *c = entry->d;
		struct extent_info *first;
		uint64_t size, sort_key;
		bool skip = false;

		if (! c || c->isdir || c->isslink || c->deleted)
			continue;

		/* Peek at size + first extent under c's contents_lock. */
		acquireread_mrsw(&c->contents_lock);
		size = c->size;
		if (size == 0 || size > priv->file_size_max || c->dirty ||
		    c->iosched_priv != NULL) {
			skip = true;
		}
		first = TAILQ_FIRST(&c->extentlist);
		if (! first)
			skip = true;
		if (skip) {
			releaseread_mrsw(&c->contents_lock);
			continue;
		}
		/* Sort key: prefer lower partitions first, then block. Using the
		 * logical partition id as a rough proxy (IP < DP in practice). */
		sort_key = ((uint64_t)(unsigned char)first->start.partition << 48) |
		           (first->start.block & 0x0000FFFFFFFFFFFFULL);
		releaseread_mrsw(&c->contents_lock);

		/* Skip if already cached. Snapshot under cache lock. */
		{
			struct ra_cache_entry *existing;
			uint64_t key = c->uid;
			ltfs_thread_mutex_lock(&priv->cache_mutex);
			HASH_FIND(hh, priv->cache_hash, &key, sizeof(key), existing);
			ltfs_thread_mutex_unlock(&priv->cache_mutex);
			if (existing)
				continue;
		}

		/* Bump numhandles so the dentry survives across the worker call. */
		acquirewrite_mrsw(&c->meta_lock);
		if (c->deleted) {
			releasewrite_mrsw(&c->meta_lock);
			continue;
		}
		c->numhandles++;
		releasewrite_mrsw(&c->meta_lock);

		if (count == capacity) {
			size_t newcap = capacity ? capacity * 2 : 32;
			struct ra_work_item *grown = realloc(items, newcap * sizeof(*items));
			if (! grown) {
				/* OOM: release this ref and give up on remaining children. */
				fs_release_dentry(c);
				break;
			}
			items = grown;
			capacity = newcap;
		}
		items[count].d = c;
		items[count].sort_key = sort_key;
		items[count].size = size;
		count++;
	}
	releaseread_mrsw(&dir->contents_lock);

	if (count == 0) {
		free(items);
		return;
	}

	work = calloc(1, sizeof(*work));
	if (! work) {
		size_t i;
		for (i = 0; i < count; i++)
			fs_release_dentry(items[i].d);
		free(items);
		return;
	}
	work->items = items;
	work->count = count;

	ltfs_thread_mutex_lock(&priv->queue_mutex);
	if (priv->work_tail)
		priv->work_tail->next = work;
	else
		priv->work_head = work;
	priv->work_tail = work;
	ltfs_thread_cond_signal(&priv->queue_cond);
	ltfs_thread_mutex_unlock(&priv->queue_mutex);
}
