#include <stdio.h>
#include <Windows.h>

// Function to retrive the shellcode
BOOL ReadFileBinary(IN LPCSTR FileName, IN PBYTE* ppFileBuffer, IN PDWORD pdwFileSize) {

	HANDLE	hFile = INVALID_HANDLE_VALUE;	// The handle for the file
	DWORD	dwFileSize = 0;					// The size of the file
	DWORD	dwBytesRead = 0;					// Number of bytes readed
	PBYTE	pBufferAddress = NULL;					// Buffer to store the shellcode which is inside the file

	// Create a handle for the file
	hFile = CreateFileA(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to create a handle, Error : %d \n", GetLastError());
		return FALSE;
	}

	// Retrieve the size of the file
	dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == INVALID_FILE_SIZE) {
		printf("Failed to get the size of the file, Error : %d \n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	// Allocate a buffer to store the content of the file
	pBufferAddress = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pBufferAddress == NULL) {
		printf("[!] Failed to allocate a buffer for the file, Error : %d \n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	// Retrieve the content of the file and put it inside the allocated buffer
	if (!ReadFile(hFile, pBufferAddress, dwFileSize, &dwBytesRead, NULL) || dwFileSize != dwBytesRead) {
		printf("Failed to read content of the file, Error : %d", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	*ppFileBuffer = pBufferAddress; // Pointer used in the main
	*pdwFileSize = dwFileSize;		// Pointer used in the main

	CloseHandle(hFile); // Close the handle

	return TRUE;

}

// Function to create the file containing the encrypted shellcode
BOOL WriteFileBinary(IN LPCSTR pFileName, IN PBYTE pFileBuffer, IN DWORD dwFileSize) {

	HANDLE	hFile = INVALID_HANDLE_VALUE;	// Handle for the file
	DWORD	dwNumberOfBytesWritten = 0;

	// Create a handle for the file
	hFile = CreateFileA(pFileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] Failed create the file, Error : %d \n", GetLastError());
		return FALSE;
	}

	// Write the encrypted shellcode inside a new file
	if (!WriteFile(hFile, pFileBuffer, dwFileSize, &dwNumberOfBytesWritten, NULL) || dwFileSize != dwNumberOfBytesWritten) {
		printf("[!] Failed to write the encrypted payload into the file, Error : %d \n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	CloseHandle(hFile); // Close the handle

	return TRUE;
}