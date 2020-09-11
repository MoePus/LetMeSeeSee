#include "windows.h"
#include "PE/PE.h"
#include "winternl.h"
#include "CUnderscore.h"
#include "InjectInit.h"
#include "bin_util.h"
#include <iostream>
#include <atomic>

PPEB get_peb()
{
#if defined(_M_X64) // x64
	auto teb = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#else // x86
	auto teb = reinterpret_cast<PTEB>(__readfsdword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#endif
	auto peb = teb->ProcessEnvironmentBlock;
	return peb;
}

struct X_LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	_ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
};

size_t MGetModuleHandle(const char* dllName)
{
	if (!dllName)
	{
		return 0;
	}
	auto peb = get_peb();
	auto dll_list = peb->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY entry_tail = &dll_list;
	PLIST_ENTRY entry = entry_tail->Flink;

	wchar_t wideDllName[260] = { 0 };
	for (int i = 0; i < strlen(dllName); i++)
	{
		wideDllName[i] = dllName[i];
	}

	do {
		auto mod = (X_LDR_DATA_TABLE_ENTRY*)entry;
		entry = entry->Flink;

		if (_wcsicmp(mod->BaseDllName.Buffer, wideDllName) == 0)
			return (size_t)mod->DllBase;

	} while (entry != entry_tail->Flink);

	return 0;
}

size_t MGetProcAddress(size_t mod, const char* procName)
{
	if (!mod || !procName)
	{
		return 0;
	}

	using namespace Jyu::PE;
	auto pe = PEViewer(mod);
	auto NTHeader = pe.getNtHeader();
	auto ExportDict = NTHeader->OptionalHeader.DataDirectory[0];

	if (!ExportDict.VirtualAddress.rva || !ExportDict.Size)
	{
		return 0;
	}

	auto Exps = (IMAGE_EXPORT_DIRECTORY*)ExportDict.VirtualAddress.with(mod);
	PDWORD pNamesAddr = (PDWORD)(mod + Exps->AddressOfNames);
	PWORD  pOrdisAddr = (PWORD)(mod + Exps->AddressOfNameOrdinals);
	PDWORD pFuncsAddr = (PDWORD)(mod + Exps->AddressOfFunctions);

	for (unsigned i = 0; i < Exps->NumberOfNames; i++)
	{
		PCSTR pszName = (PCSTR)(mod + pNamesAddr[i]);
		WORD nIndex = pOrdisAddr[i];
		if (strcmp(procName, pszName) == 0)
			return mod + pFuncsAddr[nIndex];
	}
	return 0;
}

void FixImportTable()
{
	auto kernel32 = MGetModuleHandle("kernel32.dll");

	using FNVirtualProtect = decltype(&VirtualProtect);
	using FNGetProcAddress = decltype(&GetProcAddress);
	using FNGetModuleHandle = decltype(&GetModuleHandleA);
	auto VirtualProtect = (FNVirtualProtect)MGetProcAddress(kernel32, "VirtualProtect");
	auto KGetProcAddress = (FNGetProcAddress)MGetProcAddress(kernel32, "GetProcAddress");
	auto KGetModuleHandle = (FNGetModuleHandle)MGetProcAddress(kernel32, "GetModuleHandleA");

	using namespace Jyu::PE;
	auto base = GetCurrentModule();
	auto pe = PEViewer(base);
	auto NTHeader = pe.getNtHeader();
	auto ImportDict = NTHeader->OptionalHeader.DataDirectory[1];
	auto ides = (IMAGE_IMPORT_DESCRIPTOR*)ImportDict.VirtualAddress.with(base);

	while (true)
	{
		if (!ides->Name && !ides->FirstThunk)
		{
			break;
		}

		auto dllName = RVA32<char>(ides->Name).with(base);

		auto mod = KGetModuleHandle(dllName);
		if (!mod)
		{
			continue;
		}
		size_t* ord = RVA32<size_t>(ides->OriginalFirstThunk).with(base);
		size_t* pointer = RVA32<size_t>(ides->FirstThunk).with(base);

		while (true)
		{
			if (!*pointer)
			{
				break;
			}

			DWORD ordOffset = *(DWORD*)ord;
			if (ordOffset < 64)
			{
				break;
			}

			auto current = pointer;
			pointer++;
			ord++;

			if (ordOffset & 0x80000000)
			{
				continue;
			}

			char* funcName = RVA32<char>(ordOffset).with(base) + 2;


			size_t localAddr = (size_t)KGetProcAddress((HMODULE)mod, funcName);

			DWORD oldProtect = 0;
			VirtualProtect(current, sizeof(size_t), PAGE_READWRITE, &oldProtect);

			*(size_t*)current = localAddr;

			VirtualProtect(current, sizeof(size_t), oldProtect, &oldProtect);
		}

		ides++;
	}
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
);
extern "C" LRESULT CALLBACK WindowHookProc(int Code, WPARAM wParam, LPARAM lParam);

int SelfInject(HWND hwnd)
{
	auto lib = GetCurrentModule();
	auto tid = GetWindowThreadProcessId(hwnd, 0);
	if (!tid)
	{
		return 1;
	}
	auto user32 = GetModuleHandleA("user32.dll");

	auto SetWindowsHookExAW = GetProcAddress(user32, "SetWindowsHookExAW");
#if defined(_M_X64)
	using FNType_SetWindowsHookEx = HHOOK(*)(
		HMODULE mod,
		void* fileName,
		DWORD threadId,
		int hookId,
		HOOKPROC fProc,
		bool bAscii);
	const char* pcallop = BinUtil::findPattern((char*)SetWindowsHookExAW + 168, 32, "E8 ?? ?? ?? ?? 48 8B");
#else
	using FNType_SetWindowsHookEx = HHOOK(__fastcall*)(
		HMODULE mod,
		void* fileName,
		DWORD threadId,
		int hookId,
		HOOKPROC fProc,
		bool bAscii);
	const char* pcallop = BinUtil::findPattern((char*)SetWindowsHookExAW + 168, 32, "E8 ?? ?? ?? ?? 8B");
#endif
	
	auto _SetWindowsHookEx = (FNType_SetWindowsHookEx)((size_t)pcallop + 5 + *(int*)(pcallop + 1));
	wchar_t Path[260] = { 0 };
	GetModuleFileNameW((HMODULE)lib, Path, 260);

	auto hhook = _SetWindowsHookEx((HMODULE)(0x3939),
		Path,
		tid,
		WH_CBT,
		(HOOKPROC)((size_t)&WindowHookProc - (size_t)lib + (size_t)0x3939),
		0);

	for (int i = 0; i < 24; i++)
	{
		auto proced = SendMessageW(hwnd, WM_ACTIVATE, WA_CLICKACTIVE, 0);
		proced = SendMessageW(hwnd, WM_MOUSEMOVE, MK_LBUTTON, rand());
		if (i > 10)
		{
			SetFocus(hwnd);
		}
		proced = SendMessageW(hwnd, WM_ACTIVATEAPP, TRUE, tid);
		SetFocus(GetDesktopWindow());
		if (i > 10)
		{
			SetForegroundWindow(hwnd);
		}
		putchar('.');
	}
	return 0;
}

extern "C" BOOL WINAPI _CRT_INIT(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
std::atomic<int> lock = -1;
LRESULT CALLBACK WindowHookProc(int Code, WPARAM wParam, LPARAM lParam)
{
	if (lock++ < 0)
	{
		FixImportTable();
		wchar_t Path[260] = { 0 };
		GetModuleFileNameW((HMODULE)GetCurrentModule(), Path, 260);
		
		_CRT_INIT((HINSTANCE)GetCurrentModule(), DLL_PROCESS_ATTACH, NULL);
		if (1 == DllMain((HMODULE)GetCurrentModule(), DLL_PROCESS_ATTACH, 0))
		{
			LoadLibraryExW(Path, 0, LOAD_LIBRARY_AS_DATAFILE); // Windows releases the dll if we dont loadlibrary weself.
		}
	}
	lock &= 0xf;
	return CallNextHookEx(NULL, Code, wParam, lParam);
}
