#include <stdio.h>
#include <Windows.h>
#include "files.h"
#include "rc4.h"

#define sKey 32 // If you want to change the size of the key, change this


// The function to generate the key
BOOL GenerateRandomKey(IN DWORD dwKeySize, OUT PBYTE* pKey) {
	HCRYPTPROV hCryptProv;
	if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		printf("[!] CryptAcquireContext failed with error: %d\n", GetLastError());
		return FALSE;
	}

	*pKey = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwKeySize);
	if (*pKey == NULL) {
		printf("[!] HeapAlloc failed with error: %d\n", GetLastError());
		CryptReleaseContext(hCryptProv, 0);
		return FALSE;
	}

	if (!CryptGenRandom(hCryptProv, dwKeySize, *pKey)) {
		printf("[!] CryptGenRandom failed with error: %d\n", GetLastError());
		HeapFree(GetProcessHeap(), 0, *pKey);
		CryptReleaseContext(hCryptProv, 0);
		return FALSE;
	}

	CryptReleaseContext(hCryptProv, 0);
	return TRUE;
}

BOOL main(int argc, char* argv[]) {

	if (argc < 3) {
		printf("[!] Missing argument(s) !\n"
			"[i] Usage : <Name of the file containing the shellcode> <Name of the file that will be created>\n"
			"[i] Usage example : Shellcrypt.exe shellcode.bin shellcode.enc \n");
		return FALSE;
	}

	PBYTE	pKey = NULL; // Pointer to the key
	PBYTE	pFileBuffer = NULL; // Pointer to the original file
	DWORD	dwFileBufferSize = 0;	// Pointer to the size of the original file
	PBYTE	pEncryptedShellcode = NULL;	// Pointer to the encrypted shellcode
	PBYTE	pDecryptedShellcode = NULL;	// Pointer to the decrypted shellcode

	// Generate the key
	if (!GenerateRandomKey(sKey, &pKey)) {
		printf("[!] Failed to generate the key !\n");
		return FALSE;
	}

	// Retrieve the shellcode and store it inside the pointer pFileBuffer
	if (!ReadFileBinary(argv[1], &pFileBuffer, &dwFileBufferSize)) {
		printf("[!] Failed to retrieve the content of the file containing the shellcode !\n"
			"Error : %d", GetLastError());
		HeapFree(GetProcessHeap(), 0, pKey);
		return FALSE;
	}
	printf("\n[i] Shellcode retrieved with success ! \n");

	// Allocate a buffer to store the encrpted shellcode
	pEncryptedShellcode = VirtualAlloc(NULL, dwFileBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pEncryptedShellcode == NULL) {
		printf("[!] Failed to allocate a buffer for the encrypted shellcode ! \n"
			"Error : %d", GetLastError());
		HeapFree(GetProcessHeap(), 0, pKey);
		VirtualFree(pFileBuffer, 0, MEM_RELEASE);
		return FALSE;
	}

	// Encryption of the shellcode using rc4 functions declared in rc4.h
	Rc4Context ctx = { 0 };
	rc4Init(&ctx, pKey, sKey);
	rc4Cipher(&ctx, pFileBuffer, pEncryptedShellcode, dwFileBufferSize);

	// Create the file that will contains the encrypted shellcode
	if (!WriteFileBinary(argv[2], pEncryptedShellcode, dwFileBufferSize)) {
		return FALSE;
	}
	printf("[i] File created with success !\n");

	// Print the key to the console, needed for the decryption
	printf("[i] The key (Keep it somewhere) : ");
	for (size_t i = 0; i < sKey; i++) {
		printf("%02x", pKey[i]);
	}
	printf("\n");

	// Release the buffers
	HeapFree(GetProcessHeap(), 0, pKey);
	VirtualFree(pFileBuffer, 0, MEM_RELEASE);
	VirtualFree(pEncryptedShellcode, 0, MEM_RELEASE);


	return TRUE;
}
