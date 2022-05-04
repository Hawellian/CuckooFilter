#ifndef _CUCKOO_FILTER_H_
#define _CUCKOO_FILTER_H_

// #define CUCKOO_DBG

#include <stdint.h>
#include "mozilla-sha1/sha1.h"

typedef uint64_t app_cuckoo_hash_t;

struct app_cuckoo
{
    struct hash_slot_cache *buckets;
    uint64_t bucket_num;
};

app_cuckoo_hash_t app_cuckoo_hash(uint8_t *data, uint32_t len);

struct app_cuckoo *app_cuckoo_alloc(struct app_cuckoo *table, int socket_id, uint64_t n);

void app_cuckoo_free(struct app_cuckoo *c);

int app_cuckoo_add(struct app_cuckoo *c, app_cuckoo_hash_t fgpt);

int app_cuckoo_del(struct app_cuckoo *c, app_cuckoo_hash_t fgpt);

int app_cuckoo_chk(struct app_cuckoo *c, app_cuckoo_hash_t fgpt);

int app_cuckoo_save(struct app_cuckoo *c, const char *filename);

struct app_cuckoo *app_cuckoo_load(const char *filename);

#endif /* _CUCKOO_FILTER_H_ */
