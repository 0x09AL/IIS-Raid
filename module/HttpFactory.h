#pragma once

#include <Windows.h>
#include <httpserv.h>
#include "Functions.h"

class CMyHttpModule : public CHttpModule
{
public:

    REQUEST_NOTIFICATION_STATUS OnSendResponse(IN IHttpContext* pHttpContext, IN ISendResponseProvider* pProviderss);
    
};

class CMyHttpModuleFactory : public IHttpModuleFactory
{
public:
    
    HRESULT GetHttpModule( OUT CHttpModule** ppModule, IN IModuleAllocator*)
    {
        CMyHttpModule* pModule = NULL;
        pModule = new CMyHttpModule();
        *ppModule = pModule;
        pModule = NULL;
        return S_OK;
    }

    void Terminate()
    {
        delete this;
    }
};


