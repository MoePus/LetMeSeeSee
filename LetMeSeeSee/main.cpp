#include <iostream>
#include <filesystem>
#include <set>
#define NOMINMAX
#include "windows.h"
#include "InjectInit.h"
#include "../minhook/include/MinHook.h"


extern "C"
{
    typedef struct _UNICODE_STRING
    {
        USHORT Length;
        USHORT MaximumLength;
        _Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
    } UNICODE_STRING, * PUNICODE_STRING;

    typedef struct _PUBLIC_OBJECT_BASIC_INFORMATION {
        ULONG Attributes;
        ULONG GrantedAccess;
        ULONG HandleCount;
        ULONG PointerCount;
        ULONG Reserved[10];    // reserved for internal use
    } PUBLIC_OBJECT_BASIC_INFORMATION, * PPUBLIC_OBJECT_BASIC_INFORMATION;

    typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
        UNICODE_STRING TypeName;
        ULONG Reserved[22];    // reserved for internal use
    } PUBLIC_OBJECT_TYPE_INFORMATION, * PPUBLIC_OBJECT_TYPE_INFORMATION;

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtQueryObject(
            _In_opt_ HANDLE Handle,
            _In_ int ObjectInformationClass,
            _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
            _In_ ULONG ObjectInformationLength,
            _Out_opt_ PULONG ReturnLength
        );
}

bool isFileObjReadOnly(HANDLE hObj)
{
    PUBLIC_OBJECT_BASIC_INFORMATION basicInfo;
    ULONG outSize = 0;
    auto status = NtQueryObject(hObj, 0,
        &basicInfo, sizeof(basicInfo), &outSize);
    if (status >= 0)
    {
        auto access = basicInfo.GrantedAccess & 0b111;
        if (((access & 0b110) == 0) && ((access & 1) == 1))
        {
            return true;
        }
    }
    return false;
}

bool isFileObj(HANDLE hObj)
{
    bool bRes = false;
    char buffer[4096];
    __PUBLIC_OBJECT_TYPE_INFORMATION* typeInfo = (__PUBLIC_OBJECT_TYPE_INFORMATION*)buffer;
    ULONG outSize = 0;
    auto status = NtQueryObject(hObj, 2, 0, 0, &outSize);
    if (outSize > 0x60 && outSize < 4096)
    {
        if (typeInfo)
        {
            status = NtQueryObject(hObj, 2, typeInfo, outSize, &outSize);
            
            if (status >= 0 && typeInfo->TypeName.Buffer && typeInfo->TypeName.Length == 8)
            {
                if (_wcsicmp(typeInfo->TypeName.Buffer, L"File") == 0)
                {
                    bRes = true;
                }
            }
        }
    }
    return bRes;
}

std::filesystem::path ProgramFolder;
std::filesystem::path WindowsFolder(L"C:\\Windows\\");
bool isChildPath(std::filesystem::path parent, std::filesystem::path child)
{
    auto lenParent = std::distance(ProgramFolder.begin(), ProgramFolder.end());
    auto lenChild = std::distance(child.begin(), child.end());
    if (lenParent > lenChild)
        return false;

    return std::equal(ProgramFolder.begin(), ProgramFolder.end(), child.begin());
}

std::set<std::wstring> knownFileSet;
bool isKnownFile(HANDLE hObj)
{
    wchar_t path[261] = { 0 };
    if (GetFinalPathNameByHandleW(hObj, path, 260, VOLUME_NAME_DOS) > 7)
    {
        auto child = std::filesystem::path(path + 4);
        if (isChildPath(ProgramFolder, child))
        {
            return true;
        }
        if (isChildPath(WindowsFolder, child))
        {
            return true;
        }

        auto inserted = knownFileSet.insert(path);
        if (!inserted.second)
            return true;
    }
    return false;
}

void* ori_CloseHandle = 0;
bool __stdcall CloseHandle_detour(HANDLE hObj)
{
    if (isFileObj(hObj))
    {
        if (isFileObjReadOnly((hObj)))
        {
            if (!isKnownFile(hObj))
            {
                SetLastError(0);
                return 1;
            }
        }
    }
    auto fn = (decltype(&CloseHandle_detour)(ori_CloseHandle));
    return fn(hObj);
}

void initProgramFolder()
{
    wchar_t exePath[261] = { 0 };
    GetModuleFileName(GetModuleHandleA(0), exePath, 260);
    std::filesystem::path fs(exePath);
    ProgramFolder = fs.parent_path();
}

int main()
{
    DWORD hWnd;
    std::cout << "Input hwnd (hex): ";
    std::cin >> std::hex >> hWnd;
    SelfInject((HWND)hWnd);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        initProgramFolder();

        MessageBoxA(0, "Injected", "Notice", 0);
        MH_Initialize();
        void* chtarget = 0;
        MH_CreateHookApiEx(L"ntdll.dll", "NtClose", CloseHandle_detour, &ori_CloseHandle, &chtarget);
        MH_EnableHook(chtarget);

        return 1;
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
    
    return 1;
}
