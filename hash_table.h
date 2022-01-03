#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "linked_list.h"

#ifdef __cplusplus
#define CONSTEXPR constexpr

extern "C" {
#else
#define CONSTEXPR
#endif

struct hash_table_item
{
    struct hash_table_item* next;
    uint64_t key;
    void* value;
};

struct hash_table
{
    struct hash_table_item** items;
    size_t size;
};

struct hash_table_const
{
    struct hash_table_item** items;
    size_t size;
    struct hash_table_item* base;
    size_t item_count;
};

CONSTEXPR uint64_t hash_string_djb2(const char* str);
CONSTEXPR uint32_t hash_string_crc32_nolookup(const char* s);

void print_hash_table(struct hash_table* table);
void* search_linked_list(struct hash_table_item* head, uint64_t key);
struct hash_table_item* create_hash_table_item(uint64_t key, void* value);
void free_hash_table_item(struct hash_table_item* item);
struct hash_table* create_hash_table(size_t size);
void free_hash_table(struct hash_table* table);
void hash_table_insert(struct hash_table* table, struct hash_table_item* item);
void* hash_table_search(struct hash_table* table, uint64_t key);

struct hash_table_item* create_hash_const_item(struct hash_table_const* table, uint64_t key, void* value);
struct hash_table_const* create_hash_table_const(size_t size);
void free_hash_table_const(struct hash_table_const* table);

#ifdef __cplusplus
}
#endif