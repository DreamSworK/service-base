/****************************** Module Header ******************************\
* Module Name:  SampleService.cpp
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


#include "stdafx.h"
#include "SampleService.h"
#include "event_ids.h"

BOOL CSampleService::Reboot()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	// Get a token for this process
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;

	// Get the LUID for the shutdown privilege
	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
	tkp.PrivilegeCount = 1;  
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Set the shutdown privilege for this process
	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

	if (GetLastError() != ERROR_SUCCESS)
		return FALSE;

	// Reboot the system and force all applications to close
	if (!ExitWindowsEx(EWX_REBOOT | EWX_FORCE,
		SHTDN_REASON_MAJOR_OPERATINGSYSTEM |
		SHTDN_REASON_MINOR_NETWORK_CONNECTIVITY |
		SHTDN_REASON_FLAG_PLANNED))
		return FALSE;

	return TRUE;
}

BOOL CSampleService::Ping(LPCWSTR lpszIpAddr)
{
	BOOL bResult = FALSE;

	in_addr IpAddr;
	memset(&IpAddr, 0, sizeof(IpAddr));

	if (InetPtonW(AF_INET, lpszIpAddr, &IpAddr) == 1)
	{
		HANDLE hIcmpFile = IcmpCreateFile();
		if (hIcmpFile != INVALID_HANDLE_VALUE)
		{
			char SendData[32] = "Ping";
			DWORD ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
			LPVOID ReplyBuffer = malloc(ReplySize);
			if (ReplyBuffer) {
				if (IcmpSendEcho(hIcmpFile, IpAddr.S_un.S_addr, SendData, sizeof(SendData), NULL, ReplyBuffer, ReplySize, 1000))
				{
					auto pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
					bResult = pEchoReply->Status == IP_SUCCESS;
				}
				free(ReplyBuffer);
			}
			IcmpCloseHandle(hIcmpFile);
		}
	}

	wstring infoMsg = SERVICE_DISP_NAME L": Pinging ";
	infoMsg += lpszIpAddr;
	WriteLogEntry(infoMsg.c_str(), bResult ? EVENTLOG_INFORMATION_TYPE : EVENTLOG_WARNING_TYPE, MSG_OPERATION, CATEGORY_SERVICE);

	m_Errors = bResult ? 0 : m_Errors + 1;
	if (m_Errors >= SERVICE_MAX_ERRORS)
	{
		WriteLogEntry(SERVICE_DISP_NAME L": Critical errors found. Need restart...", EVENTLOG_ERROR_TYPE, MSG_OPERATION, CATEGORY_SERVICE);
		Reboot();
	}

	return bResult;
}

CSampleService::CSampleService(PCWSTR pszServiceName,
                               BOOL fCanStop,
                               BOOL fCanShutdown,
                               BOOL fCanPauseContinue) :
    CServiceBase(pszServiceName, fCanStop, fCanShutdown, fCanPauseContinue, MSG_SVC_FAILURE, CATEGORY_SERVICE)
{
	m_Errors = 0;
    m_bIsStopping = FALSE;

    m_hHasStoppedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (m_hHasStoppedEvent == NULL)
    {
        throw GetLastError();
    }
}

void CSampleService::OnStart(DWORD /* useleses */, PWSTR* /* useless */)
{
    const wchar_t* wsConfigFullPath = SERVICE_CONFIG_FILE;
    bool bRunAsService = true;

    // Log a service start message to the Application log.
    WriteLogEntry(SERVICE_DISP_NAME L" is starting...", EVENTLOG_INFORMATION_TYPE, MSG_STARTUP, CATEGORY_SERVICE);

    if (m_argc > 1)
    {
        bRunAsService = (_wcsicmp(SERVICE_CMD, m_argv[1]) == 0);

        // Check if the config file was specified on the service command line
        if (m_argc > 2) // the argument at 1 should be "run mode", so we start at 2
        {
            if (_wcsicmp(L"-config", m_argv[2]) == 0)
            {
                if (m_argc > 3)
                {
                    wsConfigFullPath = m_argv[3];
                }
                else
                {
                    throw exception("no configuration file name");
                }
            }
        }
    }
    else
    {
        WriteLogEntry(SERVICE_DISP_NAME L": No run mode specified.", EVENTLOG_ERROR_TYPE, MSG_STARTUP, CATEGORY_SERVICE);
        throw exception("no run mode specified");
    }

    try
    {
        // Here we would load configuration file
        // but instead we're just writing to event log the configuration file name
        wstring infoMsg = SERVICE_DISP_NAME L": Reading configuration from ";
		infoMsg += wsConfigFullPath;
        WriteLogEntry(infoMsg.c_str(), EVENTLOG_INFORMATION_TYPE, MSG_STARTUP, CATEGORY_SERVICE);
    }
    catch (exception const& e)
    {
        WCHAR wszMsg[MAX_PATH];

        _snwprintf_s(wszMsg, _countof(wszMsg), _TRUNCATE, SERVICE_DISP_NAME L": Error reading configuration %S", e.what());

        WriteLogEntry(wszMsg, EVENTLOG_ERROR_TYPE, MSG_STARTUP, CATEGORY_SERVICE);
    }

    if (bRunAsService)
    {
        WriteLogEntry(SERVICE_DISP_NAME L" will run as a service.", EVENTLOG_INFORMATION_TYPE, MSG_STARTUP, CATEGORY_SERVICE);

        // Add the main service function for execution in a worker thread.
        if (!CreateThread(NULL, 0, ServiceRunner, this, 0, NULL))
        {
            WriteLogEntry(SERVICE_DISP_NAME L" couldn't create worker thread.", EVENTLOG_ERROR_TYPE, MSG_STARTUP, CATEGORY_SERVICE);
        }
    }
    else
    {
        wprintf(SERVICE_DISP_NAME L" is running as a regular process.\n");

        CSampleService::ServiceRunner(this);
    }
}

CSampleService::~CSampleService()
{
}

void CSampleService::Run()
{
    OnStart(0, NULL);
}

DWORD __stdcall CSampleService::ServiceRunner(void* self)
{
    CSampleService* pService = (CSampleService*)self;

    pService->WriteLogEntry(SERVICE_DISP_NAME L" has started.", EVENTLOG_INFORMATION_TYPE, MSG_STARTUP, CATEGORY_SERVICE);

    // Periodically check if the service is stopping.
    for (bool once = true; !pService->m_bIsStopping; once = false)
    {
        if (once)
        {
            pService->WriteLogEntry(SERVICE_DISP_NAME L" is working...", EVENTLOG_INFORMATION_TYPE, MSG_OPERATION, CATEGORY_SERVICE);
        }

		pService->Ping(SERVICE_IP);

        Sleep(SERVICE_TIMEOUT);
    }

    // Signal the stopped event.
    SetEvent(pService->m_hHasStoppedEvent);
    pService->WriteLogEntry(SERVICE_DISP_NAME L" has stopped.", EVENTLOG_INFORMATION_TYPE, MSG_SHUTDOWN, CATEGORY_SERVICE);

    return 0;
}

void CSampleService::OnStop()
{
    // Log a service stop message to the Application log.
    WriteLogEntry(SERVICE_DISP_NAME L" is stopping", EVENTLOG_INFORMATION_TYPE, MSG_SHUTDOWN, CATEGORY_SERVICE);

    // Indicate that the service is stopping and wait for the finish of the
    // main service function (ServiceWorkerThread).
    m_bIsStopping = TRUE;

    if (WaitForSingleObject(m_hHasStoppedEvent, INFINITE) != WAIT_OBJECT_0)
    {
        throw GetLastError();
    }
}
