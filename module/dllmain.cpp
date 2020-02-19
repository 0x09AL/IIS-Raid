// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <httpserv.h>
#include "HttpFactory.h"

CMyHttpModuleFactory * pFactory = NULL;


HRESULT __stdcall RegisterModule(DWORD dwServerVersion, IHttpModuleRegistrationInfo * pModuleInfo, IHttpServer * pHttpServer)
{

   
    HRESULT hr = S_OK;
    
    // Factory class is responsible for manufacturing instance of our module for each request.
    pFactory = new CMyHttpModuleFactory(); 

    // Register for the server events.
    hr = pModuleInfo->SetRequestNotifications(pFactory, RQ_SEND_RESPONSE, 0);
    
    return hr;
}

