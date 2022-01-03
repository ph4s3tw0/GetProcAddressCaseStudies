#include "hash_table.h"

void* search_linked_list(struct hash_table_item* head, uint64_t key)
{
    do
    {
        if (head->key == key)
            return head->value;
    } while ((head = head->next));

    return NULL;
}

CONSTEXPR uint64_t hash_string_djb2(const char* str)
{
    uint64_t hash = 0x1337133713371337;
    char c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;

    return hash;
}

CONSTEXPR uint32_t hash_string_crc32_nolookup(const char* s)
{
    uint32_t crc = 0xFFFFFFFF;
    char ch = 0;

    while (ch = *(s++)) {
        for (size_t j = 0; j < 8; j++) {
            uint32_t b = (ch ^ crc) & 1;
            crc >>= 1;
            if (b) crc = crc ^ 0xEDB88320;
            ch >>= 1;
        }
    }

    return ~crc;
}

struct hash_table_item* create_hash_table_item(uint64_t key, void* value)
{
    struct hash_table_item* item = malloc(sizeof(*item));

    item->key = key;
    item->value = value;
    item->next = NULL;

    return item;
}

struct hash_table_item* create_hash_const_item(struct hash_table_const* table, uint64_t key, void* value)
{
    struct hash_table_item* item = table->base + table->item_count++;

    item->key = key;
    item->value = value;
    item->next = NULL;

    return item;
}

void free_hash_table_item(struct hash_table_item* item)
{
    free(item);
}

struct hash_table* create_hash_table(size_t size)
{
    struct hash_table* table = malloc(sizeof(*table));

    table->size = size;

    table->items = calloc(table->size, sizeof(*table->items));

    return table;
}

struct hash_table_const* create_hash_table_const(size_t size)
{
    struct hash_table_const* table = malloc(sizeof(*table));

    table->size = size;
    table->item_count = 0;

    table->items = calloc(table->size, sizeof(*table->items));
    table->base = malloc(sizeof(*table->base) * size);

    return table;
}

void free_hash_table(struct hash_table* table)
{
    struct hash_table_item* item = NULL;
    struct hash_table_item* popped = NULL;

    for (int i = 0; i < table->size; i++)
    {
        item = table->items[i];
        if (item != NULL)
        {
            /*
                Free every item in the chain

                TODO: maybe popping every value from the end isn't
                good for performance, maybe we free from the head?
            */
            do
            {
                popped = (struct hash_table_item*)pop_linked_list((struct Node*)item);

                if (popped == item)
                {
                    free_hash_table_item(item);
                    table->items[i] = NULL;
                    break;
                }

                free_hash_table_item(popped);
            } while (popped != NULL);
        }
    }

    free(table);
}

void free_hash_table_const(struct hash_table_const* table)
{
    struct hash_table_item* item = NULL;
    struct hash_table_item* popped = NULL;

    free(table->base);
    free(table->items);
    free(table);
}


void hash_table_insert(struct hash_table* table, struct hash_table_item* item)
{
    struct hash_table_item* indexed_item = NULL;

    /*
        Get hash table index
    */
    uint64_t index = item->key % table->size;

    indexed_item = table->items[index];

    if (indexed_item == NULL)
    {
        /*
            Insert item into hash index
        */
        table->items[index] = item;
    }
    else
    {
        /*
            Hash collision, prepend new item to the
            head of the chain.
            TODO: Find a way to modify existing entries without
            costing insert time complexity to become O(n)
        */
        table->items[index] = (struct hash_table_item*)prepend_linked_list(
            (struct Node*)indexed_item,
            (struct Node*)item);
    }
}

void* hash_table_search(struct hash_table* table, uint64_t key)
{
    /*
        Get hash table index
    */
    uint64_t index = key % table->size;

    if (table->items[index] == NULL)
        return NULL;

    /*
        If the key at the index is different from search key,
        we have to walk the chain to find the value. We do this
        anyways as there is no need to branch here.
    */
    return search_linked_list(table->items[index], key);
}

void print_hash_table(struct hash_table* table)
{
    struct hash_table_item* item = NULL;

    /*
        Print every valid item index.
    */
    for (int i = 0; i < table->size; i++)
    {
        item = table->items[i];

        if (item)
        {
            /*
                Walk item chain to print all items
            */
            do
            {
                printf("%d:\taddr:%p\tnext:%p\n", i, item->value, item->next);
            } while ((item = item->next));
        }
    }
}