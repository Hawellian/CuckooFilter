#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "cuckoo_filter.h"

#define SECTOR_SIZE (4)                                               // length of fingerprint, Max 4B
#define ASSOC_WAY (4)                                                 // Number of slots in a bucket
#define cuckoo_hash_lsb(key, count) (((uint32_t)(key)) & (count - 1)) // First storage bucket position
#define force_align(addr, size) ((void *)((((uintptr_t)(addr)) + (size)-1) & ~((size)-1)))

static uint64_t capacity;
struct hash_slot_cache
{
    uint32_t tag[ASSOC_WAY]; /* summary of key */
};

static inline uint64_t next_pow_of_2(uint64_t x)
{
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x |= x >> 32;
    x++;
    return x;
}

inline uint32_t fingerp(app_cuckoo_hash_t key) // Ensure fingerprint is not 0
{
    uint32_t tag;
    tag = ((uint32_t)(key >> 32) & ((1ULL << 8 * SECTOR_SIZE) - 1));
    tag += (tag == 0);
    return tag;
}

inline uint32_t cuckoo_hash_msb(app_cuckoo_hash_t key, uint64_t count) // Second storage bucket position
{
    uint32_t tag;
    tag = ((key >> 32) & ((1ULL << 8 * SECTOR_SIZE) - 1));
    tag += (tag == 0);
    uint32_t ret = (((uint32_t)(cuckoo_hash_lsb(key, count) ^ (tag * 0x5bd1e995))) & (count - 1));
    return ret;
}

app_cuckoo_hash_t app_cuckoo_hash(uint8_t *data, uint32_t len)
{
    app_cuckoo_hash_t ret;
    uint8_t *key;
    key = malloc(10);
    SHA_CTX c;
    SHA1_Init(&c);
    SHA1_Update(&c, data, len);
    SHA1_Final(key, &c);
    ret = ((uint32_t *)(key))[1];
    ret = (ret << 32);
    ret |= ((uint32_t *)(key))[0];
    free(key);
    return ret;
}

static void show_hash_slots(struct app_cuckoo *table)
{
#ifdef CUCKOO_DBG
    int i, j;

    printf("List all keys in hash table (tag/status):\n");
    for (i = 0; i < table->bucket_num; i++)
    {
        printf("bucket[%04x]:", i);
        for (j = 0; j < ASSOC_WAY; j++)
        {
            printf("\t%04x/", table->buckets[i].tag[j]);
        }
        printf("\n");
    }
#endif
}

static int cuckoo_hash_collide(struct app_cuckoo *table, uint32_t *tag)
{
    int i, j, k, alt_cnt;
    uint32_t old_tag[3];

    /* Kick out the old bucket and move it to the alternative bucket. */
    i = 1;
    alt_cnt = 0;
    k = rand() % ASSOC_WAY;
    old_tag[0] = tag[0];
    old_tag[2] = table->buckets[tag[0]].tag[k];
    old_tag[1] = ((uint32_t)(old_tag[0] ^ (old_tag[2] * 0x5bd1e995))) & (table->bucket_num - 1);
    table->buckets[tag[0]].tag[k] = tag[2];

KICK_OUT:
    for (j = 0; j < ASSOC_WAY; j++)
    {
        if (table->buckets[old_tag[i]].tag[j] == 0)
        {
            table->buckets[old_tag[i]].tag[j] = old_tag[2];
            break;
        }
    }

    if (j == ASSOC_WAY)
    {
        if (++alt_cnt > 256)
        {
            return 1;
        }

        k = rand() % ASSOC_WAY;
        uint32_t tmp_tag = table->buckets[old_tag[i]].tag[k];
        table->buckets[old_tag[i]].tag[k] = old_tag[2];
        old_tag[2] = tmp_tag;
        old_tag[0] = old_tag[i];
        old_tag[1] = ((uint32_t)(old_tag[0] ^ (old_tag[2] * 0x5bd1e995))) & (table->bucket_num - 1);
        i ^= 1;

        goto KICK_OUT;
    }

    return 0;
}

int app_cuckoo_chk(struct app_cuckoo *table, app_cuckoo_hash_t key)
{
    uint32_t i, j, tag[3];
    tag[0] = cuckoo_hash_lsb(key, table->bucket_num);
    tag[2] = fingerp(key);
#ifdef CUCKOO_DBG
    tag[1] = cuckoo_hash_msb(key, table->bucket_num);
    printf("get t0:%x t1:%x t2:%x\n", tag[0], tag[1], tag[2]);
#endif

    for (i = 0; i < ASSOC_WAY; i++)
    {
        if (tag[2] == table->buckets[tag[0]].tag[i])
        {
            return 0;
        }
    }

    tag[1] = cuckoo_hash_msb(key, table->bucket_num);
    if (i == ASSOC_WAY)
    {
        for (j = 0; j < ASSOC_WAY; j++)
        {
            if (tag[2] == table->buckets[tag[1]].tag[j])
            {
                return 0;
            }
        }

        if (j == ASSOC_WAY)
        {
#ifdef CUCKOO_DBG
            printf("Key not exists!\n");
#endif
            return -1;
        }
    }

    return 0;
}

int app_cuckoo_add(struct app_cuckoo *table, app_cuckoo_hash_t key)
{
    int i, j;
    uint32_t tag[3];
    tag[0] = cuckoo_hash_lsb(key, table->bucket_num);

    tag[2] = fingerp(key);
#ifdef CUCKOO_DBG
    tag[1] = cuckoo_hash_msb(key, table->bucket_num);
    printf("put  t0:%x t1:%x fp:%04x\n", tag[0], tag[1], tag[2]);
#endif

    for (i = 0; i < ASSOC_WAY; i++)
    {
        if (table->buckets[tag[0]].tag[i] == 0)
        {
            table->buckets[tag[0]].tag[i] = tag[2];
            break;
        }
    }

    if (i == ASSOC_WAY)
    {
        tag[1] = cuckoo_hash_msb(key, table->bucket_num);
        for (j = 0; j < ASSOC_WAY; j++)
        {
            if (table->buckets[tag[1]].tag[j] == 0)
            {
                table->buckets[tag[1]].tag[j] = tag[2];
                break;
            }
        }

        if (j == ASSOC_WAY)
        {
            if (cuckoo_hash_collide(table, tag))
            {
#ifdef CUCKOO_DBG
                printf("Hash table collision!\n");
#endif
                return -1;
            }
        }
    }

    show_hash_slots(table);

    return 0;
}

int app_cuckoo_del(struct app_cuckoo *table, app_cuckoo_hash_t key)
{
    uint32_t i, j, tag[3];

    tag[0] = cuckoo_hash_lsb(key, table->bucket_num);
    tag[2] = fingerp(key);

#ifdef CUCKOO_DBG
    tag[1] = cuckoo_hash_msb(key, table->bucket_num);
    printf("delete: t0:%x t1:%x\n", tag[0], tag[1]);
#endif

    /* Insert new key into hash buckets. */

    for (i = 0; i < ASSOC_WAY; i++)
    {
        if (tag[2] == table->buckets[tag[0]].tag[i])
        {
            table->buckets[tag[0]].tag[i] = 0;
            return 0;
        }
    }

    if (i == ASSOC_WAY)
    {
        tag[1] = cuckoo_hash_msb(key, table->bucket_num);
        for (j = 0; j < ASSOC_WAY; j++)
        {
            if (tag[2] == table->buckets[tag[1]].tag[j])
            {
                table->buckets[tag[1]].tag[j] = 0;
                return 0;
            }
        }

        if (j == ASSOC_WAY)
        {
#ifdef CUCKOO_DBG
            printf("Key not exists!\n");
#endif
            return -1;
        }
    }
    return 0;
}

struct app_cuckoo *app_cuckoo_alloc(struct app_cuckoo *table, int socket_id, uint64_t size)
{
    capacity = next_pow_of_2(size + 1);

    table[socket_id].bucket_num = capacity / ASSOC_WAY;
    table[socket_id].buckets = malloc(table[socket_id].bucket_num * sizeof(struct hash_slot_cache));

    return &table[socket_id];
}

void app_cuckoo_free(struct app_cuckoo *table)
{
    free(table->buckets);
}

int app_cuckoo_save(struct app_cuckoo *c, const char *filename)
{
    FILE *fp;
    fp = fopen(filename, "wb");
    if (fp == NULL)
    {
        printf("Error:create %s file fail!\n", filename);
        return -1;
    }
    fwrite((const void *)&c->bucket_num, sizeof(uint64_t), 1, fp);
    fwrite(c->buckets, sizeof(struct hash_slot_cache), c->bucket_num, fp);
    fclose(fp);
    return 0;
}

struct app_cuckoo *app_cuckoo_load(const char *filename)
{
    struct app_cuckoo *c = (struct app_cuckoo *)malloc(sizeof(struct app_cuckoo *));
    FILE *fp = fopen(filename, "rb");
    if (NULL == fp)
    {
        printf("Error:Open %s file fail!\n", filename);
        return NULL;
    }
    // 1. load the size of the file
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    rewind(fp);
    printf("=== load file size:%ld (Byte) ===\n", fsize);
    // 2. load bucket number
    uint64_t num = 0;
    fread((void *)&num, sizeof(uint64_t), 1, fp);
    printf("[0] load from dbfile: bucket number -> %ld\n", num);
    c->bucket_num = num;
    // printf("[1] c->bucket_num: %ld\n", c->bucket_num);
    // 3. malloc a space to hold the cuckoo filter
    c->buckets = (struct hash_slot_cache *)malloc(num * sizeof(struct hash_slot_cache));
    memset(c->buckets, 0, num * sizeof(struct hash_slot_cache));
    fread(c->buckets, sizeof(struct hash_slot_cache), c->bucket_num, fp);
    // printf("[2] c->buckets[1]: %u\n", c->buckets[1].tag[0]);
    fclose(fp);
    return c;
}
