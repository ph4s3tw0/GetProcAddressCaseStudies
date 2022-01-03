#include "import.h"

void* GetProcAddress_BruteHash(PVOID pModuleBase, uint64_t hash)
{
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// Get the EAT
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (hash_string_djb2(pczFunctionName) == hash)
			return pFunctionAddress;
	}

	return NULL;
}

struct hash_table_const* GenerateHashTableFromExports(PVOID pModuleBase)
{
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// Get the EAT
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	struct hash_table_const* table = create_hash_table_const(pImageExportDirectory->NumberOfNames);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		struct hash_table_item* item = create_hash_const_item(table, hash_string_djb2(pczFunctionName), pFunctionAddress);

		hash_table_insert(table, item);
	}

	return table;
}

PVOID GetProcAddress_BinarySearch(PVOID base, const char* func) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_FILE_HEADER head = (PIMAGE_FILE_HEADER)((char*)base + dos->e_lfanew + sizeof(DWORD));
	PIMAGE_OPTIONAL_HEADER opt_head = (PIMAGE_OPTIONAL_HEADER)(head + 1);
	ULONG export_size = opt_head->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	ULONG export_rva = opt_head->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	if (!export_size)
		return NULL;

	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((char*)base + export_rva);

	DWORD* name_rva = (PDWORD)((char*)base + exports->AddressOfNames);

	DWORD* function_rva = (PDWORD)((char*)base + exports->AddressOfFunctions);

	WORD* ordinal = (PWORD)((char*)base + exports->AddressOfNameOrdinals);


	// binary search

	unsigned long right, left, middle;
	right = exports->NumberOfNames;
	left = 0;

	while (right != left) {
		middle = left + ((right - left) >> 1);

		int result = strcmp((char*)base + name_rva[middle], func);
		if (!result)
			return (PVOID)((char*)base + function_rva[ordinal[middle]]);
		else if (result < 0) {
			left = middle;
		}
		else {
			right = middle;
		}
	}

	return NULL;
}

void* GetProcAddress_PreGenHashTable(PVOID pModuleBase, const char* key)
{
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return;

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return;

	// Get the hash table section
	struct IMAGE_EXPORT_HASH_TABLE_DIRECTORY* pExportHashTable = VA(pModuleBase, pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress);
	DWORD hash_table_size = pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size;

	DWORD total_entries = hash_table_size / sizeof(struct IMAGE_EXPORT_HASH_TABLE_DIRECTORY);
	struct IMAGE_EXPORT_HASH_TABLE_DIRECTORY* entry = NULL;

	uint64_t hash = hash_string_djb2(key);

	DWORD index = hash % total_entries;

	entry = &pExportHashTable[index];

	if (entry->key == hash)
		return VA(pModuleBase, entry->address);
	//else if (pExportHashTable[index].key == 0)
		//return NULL;
	else
	{
		while (entry->next_index != -1)
		{
			/*
				This is the dirtiest C code in my life.
				This bit of code right here is why rust is becoming more popular
			*/
			entry = &pExportHashTable[entry->next_index % total_entries];
			if (entry->key == hash)
				return VA(pModuleBase, entry->address);
		}
	}

	return NULL;
}