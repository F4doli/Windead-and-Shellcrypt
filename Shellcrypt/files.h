#ifndef FILES_H

#define FILES_H
#include <Windows.h>

BOOL ReadFileBinary(IN LPCSTR pfileName, IN PBYTE* ppFileBuffer, IN PDWORD pdwFileSize);
BOOL WriteFileBinary(IN LPCSTR pfileName, IN PBYTE pFileBuffer, IN DWORD dwFileSize);

#endif