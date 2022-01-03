#include <Windows.h>
#include <stdint.h>
#include <benchmark/benchmark.h>
#include <array>
#include <string>
#include <unordered_map>

#include "import.h"
#include "hash_table.h"

#pragma comment (lib, "Shlwapi.lib")

std::array<const char*, 21> func_names = {
   "A_SHAFinal",
   "CsrAllocateCaptureBuffer",
   "DbgBreakPoint",
   "EtwProcessPrivateLoggerRequest",
   "KiRaiseUserExceptionDispatcher",
   "LdrAccessResource",
   "MD4Final",
   "_wcsnset_s",
   "abs",
   "bsearch",
   "ceil",
   "fabs",
   "iswctype",
   "labs",
   "mbstowcs",
   "pow",
   "qsort",
   "sin",
   "tan",
   "vDbgPrintEx",
   "wcscat" };

auto djb2_list = [] {

	std::array<uint64_t, func_names.size()> result{};
	for (size_t i = 0; i < func_names.size(); i++) {
		result[i] = hash_string_djb2(func_names[i]);
	}
	return result;

}();

std::unordered_map <uint64_t, void*> GetUnorderedMapFromExports(PVOID pModuleBase)
{
	std::unordered_map <uint64_t, void*> map = {};

	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return map;

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return map;

	// Get the EAT
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	map.reserve(pImageExportDirectory->NumberOfNames);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		map.emplace(hash_string_djb2(pczFunctionName), pFunctionAddress);
	}

	return map;
}

void BM_GetProcAddress(benchmark::State& state)
{
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");

	FARPROC func = NULL;

	for (auto _ : state)
	{
		for (int i = 0; i < func_names.size(); i++)
		{
			func = GetProcAddress(hNtdll, func_names[i]);
			if (!func)
			{
				printf("[-] Failed to find exported function\n");
				exit(-1);
			}
		}
	}
}
BENCHMARK(BM_GetProcAddress);

void BM_Brute(benchmark::State& state)
{
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");

	void* func = NULL;

	for (auto _ : state)
	{
		for (int i = 0; i < djb2_list.size(); i++)
		{
			func = GetProcAddress_BruteHash(hNtdll, djb2_list[i]);
			if (!func)
			{
				printf("[-] Failed to find exported function\n");
				exit(-1);
			}
		}
	}
}
BENCHMARK(BM_Brute);

void BM_GenHashTable(benchmark::State& state)
{
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");

	void* func = NULL;

	for (auto _ : state)
	{
		struct hash_table_const* table = GenerateHashTableFromExports(hNtdll);

		for (int i = 0; i < func_names.size(); i++)
		{
			func = hash_table_search((struct hash_table*)table, hash_string_djb2(func_names[i]));
			if (!func)
			{
				printf("[-] Failed to find exported function\n");
				exit(-1);
			}
		}

		free_hash_table_const(table);
	}
}
BENCHMARK(BM_GenHashTable);

void BM_BinarySearch(benchmark::State& state)
{
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");

	PVOID func = NULL;

	for (auto _ : state)
	{
		for (int i = 0; i < func_names.size(); i++)
		{
			func = GetProcAddress_BinarySearch(hNtdll, func_names[i]);
			if (!func)
			{
				printf("[-] Failed to find exported function\n");
				exit(-1);
			}
		}
	}
}
BENCHMARK(BM_BinarySearch);

void BM_PreGenHashTable(benchmark::State& state)
{
	HMODULE hNtdll = LoadLibraryA("ntdll_pregen.dll");

	void* func = NULL;

	for (auto _ : state)
	{
		for (int i = 0; i < func_names.size(); i++)
		{
			func = GetProcAddress_PreGenHashTable(hNtdll, func_names[i]);
			if (!func)
			{
				printf("[-] Failed to find exported function\n");
				exit(-1);
			}
		}
	}
}
BENCHMARK(BM_PreGenHashTable);

void BM_UnorderedMap(benchmark::State& state)
{
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");

	void* func = NULL;

	for (auto _ : state)
	{
		auto map = GetUnorderedMapFromExports(hNtdll);

		for (int i = 0; i < func_names.size(); i++)
		{
			try 
			{
				func = map.at(hash_string_djb2(func_names[i]));
			}
			catch (const std::exception& e)
			{
				printf("[-] Failed to find exported function\n %s\n", e.what());
				exit(-1);
			}
		}
	}
}
BENCHMARK(BM_UnorderedMap);

BENCHMARK_MAIN();