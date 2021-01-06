/****************************** Module Header ******************************\
* Module Name:  SampleService.h
* Project:      sample-service
* Copyright (c) Microsoft Corporation.
* Copyright (c) Tromgy (tromgy@yahoo.com)
*
* Provides a sample service class that derives from the service base class -
* CServiceBase. The sample service logs the service start and stop
* information to the Application event log, and shows how to run the main
* function of the service in a thread pool worker thread.
*
* This source is subject to the Microsoft Public License.
* See http://www.microsoft.com/en-us/openness/resources/licenses.aspx#MPL.
* All other rights reserved.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
* EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\***************************************************************************/

#pragma once

#include <ServiceBase.h>
#include <string>

// Default service start options.
#define SERVICE_START_TYPE       SERVICE_AUTO_START

// List of service dependencies (none)
#define SERVICE_DEPENDENCIES     L""

// Default name of the account under which the service should run
#define SERVICE_ACCOUNT          L".\\LocalSystem"

// Default password to the service account name
#define SERVICE_PASSWORD         NULL

// Configuration file
#define SERVICE_CONFIG_FILE      L"config.cfg"

// Command to run as a service
#define SERVICE_CMD              L"serve"

// Command to run as a stand-alone process
#define PROCESS_CMD              L"run"

// Service name
#define SERVICE_NAME             L"internet-service"

// Service name as displayed in MMC
#define SERVICE_DISP_NAME        L"Internet Checker"

// Service description as displayed in MMC
#define SERVICE_DESC             L"The service that checks Internet connection."

#define SERVICE_IP               L"8.8.8.8"

#define SERVICE_TIMEOUT          60 * 1000 // 1 minute

#define SERVICE_MAX_ERRORS       20 // the system will reboot if after 20 times checks is no internet connectivity

using namespace std;

class CSampleService: public CServiceBase
{
  public:
    CSampleService(PCWSTR pszServiceName,
                   BOOL fCanStop = TRUE,
                   BOOL fCanShutdown = TRUE,
                   BOOL fCanPauseContinue = FALSE
                  );
    ~CSampleService();

    virtual void OnStart(DWORD dwArgc, PWSTR *pszArgv);

    virtual void OnStop();

    static DWORD __stdcall  ServiceRunner(void* self);

    void Run();

	BOOL Ping(LPCWSTR lpszIpAddr);

	BOOL Reboot();

  private:
    DWORD m_Errors;
    BOOL m_bIsStopping;
    HANDLE m_hHasStoppedEvent;
    wstring m_wstrParam;
};

