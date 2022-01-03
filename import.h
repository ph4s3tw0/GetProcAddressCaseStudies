#pragma once

#include <Windows.h>
#include <stdint.h>

#include "hash_table.h"
#include "linked_list.h"

#ifdef __cplusplus
extern "C" {
#endif

struct IMAGE_EXPORT_HASH_TABLE_DIRECTORY
{
	uint64_t key;
	uint32_t address;
	uint32_t next_index;
};

#define VA( base, rva ) ( (PBYTE)base + rva )

void* GetProcAddress_BruteHash(PVOID pModuleBase, uint64_t hash);
struct hash_table_const* GenerateHashTableFromExports(PVOID pModuleBase);
PVOID GetProcAddress_BinarySearch(PVOID base, const char* func);
void* GetProcAddress_PreGenHashTable(PVOID pModuleBase, const char* key);

#ifdef __cplusplus
}
#endif