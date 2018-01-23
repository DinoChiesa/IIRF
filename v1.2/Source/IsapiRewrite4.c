// #define ARTIFICIAL_FAIL    1

/*

  IsapiRewrite4.c

  Ionic's Isapi Rewrite Filter [IIRF]

  ISAPI Filter that does  URL-rewriting. 
  Inspired by Apache's mod_rewrite .
  Implemented in C, does not use MFC. 


  Copyright (c) Microsoft Corporation, 2005, 2006, 2007.  All rights reserved.

  ==================================================================

  License
  ---------------------------------

  Ionic's ISAPI Rewrite Filter is an add-on to IIS that can
  rewrite URLs.  IIRF and its documentation is distributed under
  the Microsoft Permissive License, spelled out below.

  IIRF depends upon PCRE, which is licensed independently and
  separately.  Consult the License.PCRE.txt file for details.

  --------------------------------------------
  Microsoft Permissive License (Ms-PL)
  Published: October 12, 2006
  
  This license governs use of the accompanying software. If you
  use the software, you accept this license. If you do not accept
  the license, do not use the software.

  1. Definitions

  The terms "reproduce," "reproduction," "derivative works," and
  "distribution" have the same meaning here as under
  U.S. copyright law.

  A "contribution" is the original software, or any additions or
  changes to the software.

  A "contributor" is any person that distributes its contribution
  under this license.

  "Licensed patents" are a contributor's patent claims that read
  directly on its contribution.

  2. Grant of Rights

  (A) Copyright Grant- Subject to the terms of this license,
  including the license conditions and limitations in section 3,
  each contributor grants you a non-exclusive, worldwide,
  royalty-free copyright license to reproduce its contribution,
  prepare derivative works of its contribution, and distribute its
  contribution or any derivative works that you create.

  (B) Patent Grant- Subject to the terms of this license,
  including the license conditions and limitations in section 3,
  each contributor grants you a non-exclusive, worldwide,
  royalty-free license under its licensed patents to make, have
  made, use, sell, offer for sale, import, and/or otherwise
  dispose of its contribution in the software or derivative works
  of the contribution in the software.

  3. Conditions and Limitations

  (A) No Trademark License- This license does not grant you rights
  to use any contributors' name, logo, or trademarks.

  (B) If you bring a patent claim against any contributor over
  patents that you claim are infringed by the software, your
  patent license from such contributor to the software ends
  automatically.

  (C) If you distribute any portion of the software, you must
  retain all copyright, patent, trademark, and attribution notices
  that are present in the software.

  (D) If you distribute any portion of the software in source code
  form, you may do so only under this license by including a
  complete copy of this license with your distribution. If you
  distribute any portion of the software in compiled or object
  code form, you may only do so under a license that complies with
  this license.

  (E) The software is licensed "as-is." You bear the risk of using
  it. The contributors give no express warranties, guarantees or
  conditions. You may have additional consumer rights under your
  local laws which this license cannot change. To the extent
  permitted under your local laws, the contributors exclude the
  implied warranties of merchantability, fitness for a particular
  purpose and non-infringement.
  --------------------------------------------
  end-of-license

  ==================================================================
  related: 

  http://www.phys-iasi.ro/Library/Computing/Using_ISAPI/index14.htm
  http://www.codeproject.com/isapi/isapiredirector.asp
  http://support.zeus.com/doc/examples/isapi/lang.html  AllocMem
  http://www.alphasierrapapa.com/IisDev/Articles/XAspFilter/

  http://msdn.microsoft.com/library/en-us/iissdk/iis/redirecting_in_an_isapi_filter_using_sf_notify_send_raw_data.asp

  dependencies: 
  PCRE - the Perl-compatible Regular Expression library, from Hazel.  this is for pattern matching.

  to build:
  (see the makefile)

*/


#ifdef _DEBUG
char *buildFlavor = "DEBUG";
#else
char *buildFlavor = "RELEASE";
#endif

#define IIRF_FILTER_NAME "Ionic ISAPI Rewriting Filter (IIRF)"



// this is necessary for ReadDirectoryChangesW (NT4.0 or later) 
#define _WIN32_WINNT  0x0400

#include <stdio.h>
#include <tchar.h>   // for _T() macro
#include <math.h>    // for log10()
#include <share.h>   // for _SH_DENYWR menmonic
#include <time.h>
#include <crtdbg.h>  // for _CRT_ASSERT

#include <WTypes.h>
#include <HttpFilt.h>
#include <WinInet.h>

#include <pcre.h>

#include "IIRF.h"


// typedefs
typedef struct _CachedLogMessage {
    char *Data;
    struct _CachedLogMessage *Next;
} CachedLogMessage;


// statics and globals
volatile BOOL     FilterInitialized = FALSE;
volatile BOOL     TerminateWatch = FALSE;
volatile BOOL     WatcherDone = FALSE;
volatile BOOL     gAlreadyCleanedUp = FALSE;
static  BOOL   gTesting = FALSE;
CRITICAL_SECTION  g_CS;
CRITICAL_SECTION  g_CS_Logfile;
FILE *g_LogFp= NULL;
//volatile BOOL FirstLog = TRUE;  // work item 11707
char *MyFullProgramName= NULL;
IirfConfig * config= NULL; 
static char IniFileName[_MAX_PATH];
char IniFileDirectory[_MAX_PATH];
char ModuleFname[_MAX_FNAME];
static SYSTEMTIME StartupTime;
static HANDLE hGlobalSemaphore;
static HANDLE hWatcherThread= 0;
static BOOL IniFileChanged= FALSE;
static HANDLE g_hDir;
char *gIirfVersion= NULL;  // ISAPI_FILTER_VERSION_STRING;
char *gIirfBuildSig = __DATE__ " " __TIME__ ;
CachedLogMessage * MsgCache = NULL;

// externs
extern int ExcFilter(EXCEPTION_POINTERS *pExp);                // ExceptionHandler.cpp


// forward decls
void EmitCachedMessages();
void OpenLogfile() ;
void LogMessage(int level, char *format, ...); 
VOID Initialize() ;
void FreeCondList(RewriteCondition * cond) ;
void ReleaseConfig (IirfConfig * deadConfig) ;
int EvaluateRules(HTTP_FILTER_CONTEXT * pfc, 
                  HTTP_FILTER_AUTH_COMPLETE_INFO * pHeaderInfo,
                  char * subject, int depth, 
                  /* out */ char **result, /* out */ boolean * pRecordOriginalUrl);
char * GetServerVariable(PHTTP_FILTER_CONTEXT pfc, char * VariableName );
char * GetServerVariable_AutoFree( PHTTP_FILTER_CONTEXT pfc, char * VariableName );
char * GetHeader_AutoFree(
    PHTTP_FILTER_CONTEXT pfc,
    HTTP_FILTER_AUTH_COMPLETE_INFO * pHeaderInfo,
    char * VariableName );

void AwaitWatcherTermination(void) ;
int ParseRuleModifierFlags(IirfConfig * cfg, char * directive, char * pModifiers, RewriteRule *rule);
void ParseCondModifierFlags(char * pModifiers, RewriteCondition *cond);
void FreeRuleList (RewriteRule * ruleNode);




/* GetFilterVersion
 * 
 * Purpose:
 * 
 *     Required entry point for ISAPI filters.  This function
 *     is called once, when the server initially loads this DLL.
 * 
 * Arguments:
 * 
 *     pVer - Points to the filter version info structure
 * 
 * Returns:
 * 
 *     TRUE on successful initialization
 *     FALSE on initialization failure
 * 
 */
BOOL WINAPI GetFilterVersion( PHTTP_FILTER_VERSION pVer ) 
{
    LogMessage(1, "GetFilterVersion");

    if ( ! FilterInitialized ) {
        Initialize();
    }

    GetSystemTime(&StartupTime);
    
    pVer->dwFilterVersion = HTTP_FILTER_REVISION;

    // filter priority
    pVer->dwFlags |=   config->FilterPriority;
    //pVer->dwFlags |=   SF_NOTIFY_ORDER_DEFAULT ;
    //pVer->dwFlags |=   SF_NOTIFY_ORDER_HIGH ;
    //pVer->dwFlags |=   SF_NOTIFY_ORDER_MEDIUM ;
    //pVer->dwFlags |=   SF_NOTIFY_ORDER_LOW ;

    // security
    pVer->dwFlags |=  SF_NOTIFY_SECURE_PORT | SF_NOTIFY_NONSECURE_PORT ;

    // notification to allow pre-processing of headers
    //pVer->dwFlags |= SF_NOTIFY_PREPROC_HEADERS;

    // we use AUTH_COMPLETE because more server variables are parsed by then.
    pVer->dwFlags |= SF_NOTIFY_AUTH_COMPLETE;

    // this is to calculate the REQUEST_FILENAME. 
    pVer->dwFlags |= SF_NOTIFY_URL_MAP;

    // notification to allow tweaking of logs (unmangling of URLs).

    // Here, we decide whether to register for LOG events based on the need.  The
    // reason is, SF_NOTIFY_LOG is cache hostile - it will disable the IIS6/7 kernel
    // mode cache, which is bad. So, we register for this event only when the rules in the
    // config file require it.  Because the filter registers for notifications
    // only once, at filter startup, un-mangling works differently than other
    // filter settings.  It doesn't always change upon modification of the ini
    // file.
    //
    // We want to register for LOG notifications if the [U] Unmangle flag
    // is set, because we have to do something special at log time when
    // logging the unmangled URL.  If no unmangled logging is desired, then 
    // we don't register for the log notifications.
    //
    // Here's the deal: If you start the filter, and have no rules with the [U]
    // unmangle flag, then the filter will not register for LOG events. If you
    // then modify the ini file to use unmangling on one or more rules, the
    // notifications will not flow.  You need to restart the filter.  On the other hand, if
    // you have [U] on at least one active rule, and then change any other rules
    // to also use [U], those unmangle flags will become active immediately.
    //
    // Finally, in the case where at least one RewriteRule has [U], and then you
    // modify the ini file and remove all [U] flags, then the filter will continue
    // to receive SF_NOTIFY_LOG events, and the IIS6 kernel cache will continue to
    // be not used.
    //
    // When in doubt, restart the filter when changing the [U] flag for any rule. 

    if (config->WantNotifyLog)
        pVer->dwFlags |= SF_NOTIFY_LOG ; 

    strncpy_s(pVer->lpszFilterDesc, sizeof(pVer->lpszFilterDesc), gIirfVersion, _TRUNCATE );
    return TRUE; 
}




/* InitCustomFilterContext
 * 
 * Purpose:
 * 
 *     Set up the custom filter context pointer, initialize the fields.
 *     The context holds the physical path, maybe necessary if we are
 *     doing file-existence checking.  It also can hold the original URI
 *     stem, which is used when the [U] flag is applied, to log unmangled
 *     URIs. 
 * 
 */
boolean InitCustomFilterContext(HTTP_FILTER_CONTEXT * pfc)
{
    IirfRequestContext *ctx;
    if (pfc->pFilterContext!=NULL) return FALSE;  // no init

    ctx = (IirfRequestContext *) pfc->AllocMem(pfc, sizeof(IirfRequestContext), 0);
    if ( ctx == NULL ) {
        LogMessage(1, "Error Allocating Request context memory.");
        SetLastError( ERROR_NOT_ENOUGH_MEMORY );
        return FALSE;
    }
    ctx->Magic= IIRF_CONTEXT_MAGIC_NUMBER;
    ctx->OriginalUriStem = NULL;
    ctx->QueryString = NULL;
    ctx->RequestMethod = NULL;
    ctx->PhysicalPath = NULL;
    pfc->pFilterContext = ctx;

    return TRUE;
}





/* SetLoggingInfoInCustomFilterContext
 * 
 * Purpose:
 * 
 *     Set the original URL, and the request method, into the custom filter
 *     context buffer.  This info is then available in the SF_NOTIFY_LOG
 *     event for logging the "unmangled" URL.  Originally I wanted to
 *     record only the original URL.  But I found that if I do not record
 *     the Request Method (verb), the IIS log records it as NULL (empty).
 *     So we record it.
 * 
 * Arguments:
 * 
 *     pfc - HTTP_FILTER_CONTEXT - this is the thing that holds the custom 
 *           context pointer (pfc->pFilterContext).  The custom pointer should
 *           have been previously allocated. (in OnMap).
 *
 *     UriStem - the original URL stem, up to but not including the ? (if any)
 * 
 *     QueryString - the original query string,  everything following the ? (if any)
 *
 *     RequestMethod - eg, GET, POST, HEAD, OPTIONS, etc
 *
 * Returns:
 * 
 *     nothing
 * 
 */
void SetLoggingInfoInCustomFilterContext(HTTP_FILTER_CONTEXT * pfc, 
                                         char * UriStem, 
                                         char * QueryString, 
                                         char * RequestMethod
    )
{
    if (pfc->pFilterContext!=NULL) {
        IirfRequestContext *ctx = (IirfRequestContext *) pfc->pFilterContext;
        if (ctx->Magic == IIRF_CONTEXT_MAGIC_NUMBER) {
            ctx->OriginalUriStem= UriStem;
            ctx->QueryString= QueryString;
            ctx->RequestMethod= RequestMethod;
        }
        else {
            LogMessage(2, "Bad Magic number for IIRF Filter Context.");
        }
    }
}



char * Iirf_GetBuildSig() 
{
    return gIirfBuildSig;
}


/* Iirf_SystemTimeUtcToLocalTimeString
 * 
 * Purpose:
 * 
 *     Convert a SYSTEMTIME expressed in UTC to a printable string,
 *     expressed in local timezone, including the timezone string.
 * 
 * Arguments:
 * 
 *     pSystemTime - pointer to SYSTEMTIME.  It must be expressed in UTC.
 *
 * Returns:
 * 
 *     a pointer to a formatted string.  Caller must free.
 * 
 */
char * Iirf_SystemTimeUtcToLocalTimeString(SYSTEMTIME * pSystemTime)
{
    SYSTEMTIME stLocal;
    TIME_ZONE_INFORMATION tzi;
    char TimeZoneString[32];
    int sz = 54;
    char * result = malloc(sz);
    int rc;

    SystemTimeToTzSpecificLocalTime(NULL, pSystemTime, &stLocal);
    rc= GetTimeZoneInformation(&tzi);
    if ((rc==1) || (rc==2))
    {
        LPCWSTR wszTz= (rc==1)? tzi.StandardName:tzi.DaylightName;
        rc= WideCharToMultiByte(
            (UINT) CP_ACP,            // code page
            (DWORD) 0,                // conversion flags
            (LPCWSTR) wszTz,          // wide-character string to convert
            (int) wcslen(wszTz),      // number of chars in string.
            (LPSTR) TimeZoneString,   // buffer for new string
            32,                       // size of buffer
            (LPCSTR) NULL,            // default for unmappable chars
            (LPBOOL) NULL             // set when default char used
            );
        if (rc!=0)
            TimeZoneString[rc]=0;
    }
    else strcpy_s(TimeZoneString, sizeof(TimeZoneString)/sizeof(TimeZoneString[0]), "(local time)");
    
    sprintf_s(result, sz, "%d/%02d/%02d %02d:%02d:%02d %s\n", 
           stLocal.wYear, stLocal.wMonth, stLocal.wDay, 
           stLocal.wHour, stLocal.wMinute, stLocal.wSecond,
           TimeZoneString);

    return result;
}



/* Iirf_FileTimeToLocalTimeString
 * 
 * Purpose:
 * 
 *     Convert a FILETIME to a printable string, expressed in local
 *     timezone, including the timezone string.
 * 
 * Arguments:
 * 
 *     pFiletime - pointer to FILETIME.  FILETIME is always UTC.
 *
 * Returns:
 * 
 *     a pointer to a formatted string.  Caller must free.
 * 
 */
char * Iirf_FileTimeToLocalTimeString(FILETIME * pFileTime)
{
    if ( pFileTime->dwLowDateTime ==0 &&
         pFileTime->dwHighDateTime == 0)
    {
        return (char *) _strdup("(file not found)");
    }
    else
    {
        SYSTEMTIME stUtc;    
        FileTimeToSystemTime(pFileTime, &stUtc);
        return Iirf_SystemTimeUtcToLocalTimeString(&stUtc);
    }
}



BOOL GetLastUpdate(char *FileName, FILETIME * pFileTime)
{
    HANDLE hFile;
    BOOL result;
    // default value
    pFileTime->dwLowDateTime = 0;
    pFileTime->dwHighDateTime = 0;
    // Open the file;  need the handle for GetFileTime()
    hFile = CreateFile( FileName, // directory path
                        GENERIC_READ,
                        FILE_SHARE_READ|FILE_SHARE_DELETE,  
                        NULL, 
                        OPEN_EXISTING,                      // open but dont create
                        FILE_ATTRIBUTE_NORMAL,
                        NULL 
        );

    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    result= GetFileTime(hFile,
                        NULL,
                        NULL,
                        pFileTime); 
    CloseHandle(hFile);

    return result;
}


DWORD _SetReply(HTTP_FILTER_CONTEXT * pfc, char * statusMsg)
{
    pfc->ServerSupportFunction (pfc,
                                SF_REQ_SEND_RESPONSE_HEADER,
                                (PVOID)statusMsg,
                                (ULONG_PTR)"Content-Length: 0\r\n"
                                "Content-Type: text/html\r\n\r\n",
                                (ULONG_PTR) NULL );

    SetLastError( NO_ERROR );
    LogMessage(2, "DoRewrites: returning %s", statusMsg);
    return SF_STATUS_REQ_FINISHED;
}


// workitem 23459
DWORD _ReplyWithStatus(HTTP_FILTER_CONTEXT * pfc)
{
    char * lastWrite = Iirf_FileTimeToLocalTimeString(&(config->LastWriteOfIniFile));
    char * lastRead = Iirf_SystemTimeUtcToLocalTimeString(&(config->ConfigRead));
    char * startup = Iirf_SystemTimeUtcToLocalTimeString(&StartupTime);
    
    static const char * hdrFormat="Content-Length: %d\r\n"
        "Content-Type: text/html\r\n"
        "Cache-Control: private,no-store,no-cache\r\n\r\n";
    static const char * replyFormat = "<html>"
"<head>"
"    <style>\n"
"      p,tr,td,body,a { font-family: Verdana, Arial, Helvetica; font-size: 9pt }\n"
"      h1 { color: #4169E1;}\n"
"      h2 { color: #1E90FF;}\n"
"      table { border: 1 gray; padding: 0 0 0 0;}\n"
"      tr td { color: Navy; }\n"
"      tr th { color: #00008B; background: #E6E6FA; }\n"
"      td {padding: 0em 1em 0em 1em; }\n"
"    </style>\n"
        "</head>"
        "<body>"
        "<h1>IIRF Status Report</h1>\n"
        "<table border='1px'>\n"
        "<tr><th>IIRF Version</th><td>%s</td></tr>\n"
        "<tr><th>Built on</th><td>%s</td></tr>\n"
        "<tr><th>Filter DLL</th><td> %s%s.dll&nbsp;</td></tr>\n"
        "<tr><th>Started</th><td>%s</td></tr>\n"
        "<tr><th>Ini file</th><td>%s&nbsp;</td></tr>\n"
        "<tr><th>&nbsp;&nbsp;Last write</th><td>%s</td></tr>\n"
        "<tr><th>&nbsp;&nbsp;Last read</th><td>%s</td></tr>\n"
        "<tr><th>&nbsp;&nbsp;Lines</th><td> %d</td></tr>\n"
        "<tr><th>&nbsp;&nbsp;Rules</th><td> %d</td></tr>\n"
        "<tr><th>&nbsp;&nbsp;Warnings</th><td> %d</td></tr>\n"
        "<tr><th>&nbsp;&nbsp;Errors</th><td> %d</td></tr>\n"
        "<tr><th>Rewrite Engine</th><td> %s</td></tr>\n"
        "<tr><th>Remote Status Inquiry</th><td> %s</td></tr>\n"
        "<tr><th>Log file</th><td> %s</td></tr>\n"
        "<tr><th>Log level</th><td> %d</td></tr>\n"
        "<tr><th>#Requests Processed</th><td> %d</td></tr>\n"
        "</table>\n"
        "</body></html>";
    DWORD resplen;
    char* statusMsg;
    char *addlHeaders;
    int len;

    // first, build the response
    len= _scprintf(replyFormat,
                   gIirfVersion,
                   Iirf_GetBuildSig(),
                   IniFileDirectory,
                   ModuleFname,
                   startup,
                   IniFileName,
                   lastWrite,
                   lastRead,
                   
                   config->nLines,
                   config->nRules,
                   config->nWarnings,
                   config->nErrors,
                   
                   (config->EngineOff) ? "OFF" : "ON",
                   (config->AllowRemoteStatus) ? "enabled" : "disabled",
                   (config->LogFileName[0]=='\0')?"(none)":config->LogFileName,
                   config->LogLevel,
                   config->numRequestsServed) + 1;  // +1 for \0
    
    statusMsg = malloc(sizeof(char) * len);
    sprintf_s(statusMsg, len, replyFormat, 
                   gIirfVersion,
                   Iirf_GetBuildSig(),
                   IniFileDirectory,
                   ModuleFname,
                   startup,
                   IniFileName,
                   lastWrite,
                   lastRead,
                   
                   config->nLines,
                   config->nRules,
                   config->nWarnings,
                   config->nErrors,
                   
                   (config->EngineOff) ? "OFF" : "ON",
                   (config->AllowRemoteStatus) ? "enabled" : "disabled",
                   (config->LogFileName[0]=='\0')?"(none)":config->LogFileName,
                   config->LogLevel,
              config->numRequestsServed);
    
    // get the length of the response
    resplen = strlen(statusMsg);

    // embed that length into the header response
    len= _scprintf(hdrFormat, resplen) + 1;  // +1 for \0
    addlHeaders = malloc(sizeof(char) * len);
    sprintf_s(addlHeaders, len, hdrFormat, resplen);

    // emit the headers
    pfc->ServerSupportFunction (pfc,
                                SF_REQ_SEND_RESPONSE_HEADER,
                                (PVOID)"200 OK",
                                (ULONG_PTR)addlHeaders,
                                (ULONG_PTR) NULL );


    // emit the response
    pfc->WriteClient(pfc,(LPVOID)statusMsg, &resplen, 0);
    SetLastError( NO_ERROR );
    LogMessage(3, "DoRewrites: Status inquiry: returning 200 - OK");

    
    // clean up
    free(startup);
    free(lastWrite);
    free(lastRead);
    free (addlHeaders);
    free (statusMsg);
    
    return SF_STATUS_REQ_FINISHED;
}


DWORD _Forbidden(HTTP_FILTER_CONTEXT * pfc)
{
    return _SetReply(pfc,"403 Forbidden");
}

DWORD _NotFound(HTTP_FILTER_CONTEXT * pfc)
{
    return _SetReply(pfc,"404 Not Found");
}

DWORD _Gone(HTTP_FILTER_CONTEXT * pfc)
{
    return _SetReply(pfc,"410 Gone");
}

DWORD _BadRequest(HTTP_FILTER_CONTEXT * pfc)
{
    return _SetReply(pfc,"400 Bad Request");
}

DWORD _EntityTooLarge(HTTP_FILTER_CONTEXT * pfc)
{
    return _SetReply(pfc,"413 Request Entity Too Large");
}


DWORD DoRewrites(HTTP_FILTER_CONTEXT * pfc, 
                 // HTTP_FILTER_PREPROC_HEADERS * pHeaderInfo
                 HTTP_FILTER_AUTH_COMPLETE_INFO * pHeaderInfo
    ) 
{
    DWORD returnValue= SF_STATUS_REQ_NEXT_NOTIFICATION;
    char *OriginalUriStem= NULL;
    char *QueryString= NULL;
    char *OriginalUrl= NULL;
    char *RequestMethod= NULL;
    DWORD dwSize= 0;
    BOOL fRet = FALSE;

    LogMessage(3, "DoRewrites");
    
    // Get the original URL, normalized.  
    // Originally IIRF used GetHeader here, but according to http://support.microsoft.com/kb/896287
    // we should use GetServerVariable to retrieve the normalized URL on IIS6 and above.
    // HowEVER, in that case, GetServerVariable does not grab the querystring!  So we need to get both. 
    // On the other hand, on IIS5, GetHeader("url") does not return anything.  So in that case, 
    // we need to use GetHeader(). The approach we'll take is to first try GetServerVariable, 
    // then fall back to GetHeader.  
    // 
    // This change was prompted by work item 11451 
    // http://www.codeplex.com/IIRF/WorkItem/View.aspx?WorkItemId=11451
    // which pointed out that with the old mechanism, the cs-uri-stem logging field was 
    // really the entire URI, and the cs-uri-query field was empty.  

    // fRet= pHeaderInfo->GetHeader(pfc, "url", OriginalUrl, &dwSize);

    // get url
    OriginalUriStem= GetServerVariable_AutoFree(pfc, "url");
    if ((OriginalUriStem == NULL) || (OriginalUriStem[0] == 0)) {
        OriginalUriStem= GetHeader_AutoFree(pfc, pHeaderInfo, "url");
        if (OriginalUriStem == NULL) {
            returnValue= (GetLastError()== 122)
                ? _EntityTooLarge(pfc)
                : _BadRequest(pfc);
            goto DoRewrites_Finished;
        }
        else {
            char * s =  (char *) strchr(OriginalUriStem, '?');
            if (s != NULL) *s=0; // terminate at the question mark
        }
    }
    QueryString= GetServerVariable_AutoFree(pfc, "QUERY_STRING");
    dwSize= strlen(OriginalUriStem) + 1 + strlen(QueryString) + 1; 

    OriginalUrl= (char *) pfc->AllocMem(pfc, dwSize, 0);
    strcpy_s(OriginalUrl, dwSize, OriginalUriStem);
    if ((QueryString!=NULL) && (strlen(QueryString) > 0)) {
        strcat_s(OriginalUrl, dwSize, "?");
        strcat_s(OriginalUrl, dwSize, QueryString);
    }

    // get method
    RequestMethod= GetHeader_AutoFree(pfc, pHeaderInfo, "method");
    if (RequestMethod== NULL) {
        returnValue= (GetLastError()== 122)
            ? _EntityTooLarge(pfc)
            : _BadRequest(pfc);
        goto DoRewrites_Finished;
    }

    SetLastError( NO_ERROR );

    // see if we have a URL to rewrite:
    if (OriginalUrl[0]!='\0') {
        int rc;
        char * resultString;
        boolean RecordOriginalUrl= FALSE;

        // workitem 23459
        InterlockedIncrement(&(config->numRequestsServed));
        
        LogMessage(2, "DoRewrites: Url: '%s'", OriginalUrl);

        rc= EvaluateRules(pfc, pHeaderInfo, OriginalUrl, 0, &resultString, &RecordOriginalUrl);

        if (rc==0) { // no URL Rewrite result
            LogMessage(3, "DoRewrites: No Rewrite");
            SetLastError( NO_ERROR );
        }
        else if (rc==1) { // Rewrite
            LogMessage(3,"DoRewrites: Rewrite Url to: '%s'", resultString);

            // SetHeader() sets the value of the request header.  Headers should have a trailing colon, 
            // except for a few well-known values (method, url, and version). 
            // see http://msdn.microsoft.com/en-us/library/ms525099.aspx for more info. 
            pHeaderInfo->SetHeader(pfc, "url", resultString); 
            free(resultString); // assume that the SetHeader() copies the data (as opposed to copying the ptr)

            if (RecordOriginalUrl) {
                // Setting a header results in setting a server variable of the same name, but prefixed by HTTP_ .
                // In this case we will get HTTP_X_REWRITE_URL .
                // We set this to accomodate server-side apps that want to know if the URL has been rewritten.  
                // ISAPI_Rewrite does this, and some people like it.  Check the readme for more info. 
                pHeaderInfo->SetHeader(pfc, "X-Rewrite-Url:", OriginalUrl);

                SetLoggingInfoInCustomFilterContext(pfc, OriginalUriStem, QueryString, RequestMethod);
            }

            SetLastError( NO_ERROR );

        }
        // workitem 23459
        else if (rc==200) { // Inquire filter Status
            returnValue= _ReplyWithStatus(pfc);
        }
        
        else if (rc==403) { // Forbidden
            returnValue= _Forbidden(pfc);
            free(resultString);
        }
        else if (rc==404) { // Not found
            returnValue= _NotFound(pfc);
            free(resultString);
        }
        else if (rc==410) { // Gone
            returnValue= _Gone(pfc);
            free(resultString);
        }
        else { // redirect
            char codestring[12];
            // workitem 15839
            // enough to hold a URL, a Location: , a Content-Length header, and  a Connection: close
            char buf[INTERNET_MAX_URL_LENGTH + 32 + 20 + 20];  // the Modified Header

            LogMessage(3, "DoRewrites: Redirect (code=%d) Url to: '%s'", rc, resultString);

            if ( (_strnicmp(resultString,"http://", 7)==0) || (_strnicmp(resultString,"https://", 8)==0)) {
                sprintf_s(buf, sizeof(buf)/sizeof(buf[0]), "Location: %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", resultString);
            }
            else {
                char *ServerName= GetServerVariable(pfc, "SERVER_NAME");
                char *ServerPort= GetServerVariable(pfc, "SERVER_PORT");

                // Modified to support  SSL (https) requests
                char *HTTPS= GetServerVariable(pfc, "HTTPS"); 
                char *Protocol = (_strnicmp(HTTPS,"on",strlen(HTTPS)) ? "http" : "https"); 

                // workitem 17025
                // http://www.codeplex.com/IIRF/WorkItem/View.aspx?WorkItemId=17025
                // If we are using the default port for the protocol...
                if (((strcmp(ServerPort,"80")==0) && (strcmp(Protocol,"http")==0)) || 
                    ((strcmp(ServerPort,"443")==0) && (strcmp(Protocol,"https")==0)) ) {
                    sprintf_s(buf, sizeof(buf)/sizeof(buf[0]), "Location: %s://%s%s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", 
                              Protocol,
                              ServerName, 
                              resultString);
                }
                else {
                    sprintf_s(buf, sizeof(buf)/sizeof(buf[0]), "Location: %s://%s:%s%s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", 
                              Protocol,
                              ServerName, 
                              ServerPort, 
                              resultString);
                }
                free(ServerName);
                free(ServerPort);
                free(HTTPS); // Modified for SSL
            }

            // get the redirect code string, eg "302"
            _itoa_s(rc, codestring, 12, 10 );
            // The response does not need to include a string here? "(Moved Permanently)" or similar.
            // The code string is sufficient. 

            // see http://msdn.microsoft.com/en-us/library/aa503395.aspx
            pfc->ServerSupportFunction (pfc,
                                        SF_REQ_SEND_RESPONSE_HEADER, 
                                        (PVOID) codestring,  // eg, "302"
                                        (DWORD) buf,         // headers to add
                                        0);

            SetLoggingInfoInCustomFilterContext(pfc, OriginalUriStem, QueryString, RequestMethod);

            free(resultString);
            returnValue= SF_STATUS_REQ_FINISHED;
            SetLastError( NO_ERROR );
        }
    }


DoRewrites_Finished:
    // Tue, 15 Apr 2008  04:54
    // changed to use AllocMem instead of malloc.  This memory gets auto freed.
    //free(OriginalUrl);

    {
        DWORD lastError= GetLastError();
        if ( ( lastError != NO_ERROR ) && (lastError != ERROR_FILE_NOT_FOUND ))
            returnValue = SF_STATUS_REQ_ERROR;
    }

    return returnValue;
}






DWORD 
OnAuthComplete (
    HTTP_FILTER_CONTEXT *           pfc,
    HTTP_FILTER_AUTH_COMPLETE_INFO *   pACI
    )

{
    DWORD dwRetval = SF_STATUS_REQ_NEXT_NOTIFICATION;

    // Before we rewrite, we initialize the OriginalUriStem, QueryString and RequestMethod 

    // This prevents the incorrect use of OriginalUrl and RequestMethod in OnLog() 
    // preserving PhysicalPath (from OnUrlMap()).
    if (pfc!=NULL && pfc->pFilterContext !=NULL)
    {
        IirfRequestContext * ctx = (IirfRequestContext*) pfc ->pFilterContext;
        ctx->OriginalUriStem=NULL; // There is no free necessary, for any of these pointers.
        ctx->QueryString=NULL;     // They all hold pointers with request-scoped allocation, 
        ctx->RequestMethod=NULL;   // and are automatically free'd by IIS when the request terminates.
    }

    // rewrite or redirect URL as desired
    __try
    {
        dwRetval = DoRewrites(pfc, pACI);
    }
    __except ( ExcFilter(GetExceptionInformation()) )
    {
    }

    return dwRetval;
}



DWORD 
OnUrlMap (
    HTTP_FILTER_CONTEXT *   pfc,
    HTTP_FILTER_URL_MAP *   pUM
    )

{
    IirfRequestContext * ctx= NULL;
    int len;

    if (pfc==NULL) 
        return SF_STATUS_REQ_NEXT_NOTIFICATION;  // nothing to do!  

    // The SF_NOTIFY_URL_MAP event can be invoked multiple times.  Here, we
    // insure to insert PhysicalPath into pFiltercontext just once per
    // request.

    if (pfc->pFilterContext==NULL && !InitCustomFilterContext(pfc))
        return SF_STATUS_REQ_ERROR ;

    // copy the physical path information. The pUM->pszPhysicalPath field may go out of scope 
    // by the time the next notification comes by (OnAuthComplete)
    ctx= (IirfRequestContext *) pfc->pFilterContext;

    len= strlen(pUM->pszPhysicalPath) + 1; // less than or equal to pUM->cbPathBuff. 
    if (ctx->PhysicalPath==NULL)
        ctx->PhysicalPath= (char *) pfc->AllocMem(pfc, len, 0);
    else
    {
        // the pointer has already been allocated and the path copied.
        // but we want to get the latest path, so we check here to see if 
        // the existing pointer is sufficient. 
        int len2=strlen(ctx->PhysicalPath) +1;
        if (len2<len)
            // Alloc new memory if the existing pointer is insufficient capacity
            ctx->PhysicalPath= (char *) pfc->AllocMem(pfc, len, 0);
        else if (len2==len && strcmp(pUM->pszPhysicalPath,ctx->PhysicalPath)==0) 
            // They are equal. No need to copy again.
            return SF_STATUS_REQ_NEXT_NOTIFICATION;
    }

    // catch all mem allocation failures
    if ( ctx->PhysicalPath == NULL ) {
        LogMessage(1, "Error Allocating memory for Physical Path.");
        SetLastError( ERROR_NOT_ENOUGH_MEMORY );
        return SF_STATUS_REQ_ERROR ;
    }

    LogMessage(5, "OnUrlMap: storing physical path (%s), %d bytes, in ptr (0x%08x)",
               pUM->pszPhysicalPath, len, ctx->PhysicalPath);

    strcpy_s(ctx->PhysicalPath, len, pUM->pszPhysicalPath);

    return SF_STATUS_REQ_NEXT_NOTIFICATION;
}




DWORD
OnLog(
    IN HTTP_FILTER_CONTEXT * pfc,
    IN HTTP_FILTER_LOG *     pLog
    )
{
    // log an unmangled URL if possible
    if (pfc->pFilterContext != NULL) {
        // means we have context
        IirfRequestContext *ctx = (IirfRequestContext *) pfc->pFilterContext;
        if (ctx->Magic == IIRF_CONTEXT_MAGIC_NUMBER) {
            // It is possible the context exists, but no OriginalUrl nor RequestMethod was stored in it.
            // This can happen, for example, when no rewrite occurs!
            if (ctx->OriginalUriStem!=NULL) pLog->pszTarget = (CHAR *)ctx->OriginalUriStem;
            if (ctx->QueryString!=NULL) pLog->pszParameters = (CHAR *)ctx->QueryString;
            if (ctx->RequestMethod!=NULL) pLog->pszOperation = (CHAR *)ctx->RequestMethod;
        }
        else {
            LogMessage(2, "OnLog: WARNING: Bad Magic number for IIRF Filter Context.");
        }
    }

    return SF_STATUS_REQ_NEXT_NOTIFICATION;
}




// http://www.codeplex.com/IIRF/WorkItem/View.aspx?WorkItemId=17002
void myInvalidParameterHandler(
    const wchar_t* wszExpression,
    const wchar_t* wszFunction, 
    const wchar_t* wszFile, 
    unsigned int line, 
    uintptr_t pReserved)
{
    char * formatString= "WARNING: Invalid Parameter: expression(%S) func(%S) file(%S) line(%d)";
    int len= _scprintf(formatString, wszExpression,wszFunction, wszFile, line) + 1;
    char  *msg = malloc(sizeof(char) * len);
    int r= sprintf_s(msg, len, formatString,                     
                     wszExpression,wszFunction, wszFile, line);

    LogMessage(1,msg);
    free(msg);
}




// see
// http://msdn.microsoft.com/library/en-us/iissdk/html/46804d1d-829a-4dda-bece-e0ba6de31278.asp
// for order of Event notifications in ISAPI filters.
// The typical order is: 
// 
// SF_NOTIFY_READ_RAW_DATA
// SF_NOTIFY_PREPROC_HEADERS
// SF_NOTIFY_URL_MAP        -- IIRF stores physical path information here
// SF_NOTIFY_AUTHENTICATION
// SF_NOTIFY_AUTH_COMPLETE  -- IIRF does rewrites here, stores originalURl and Request method here
// SF_NOTIFY_READ_RAW_DATA
// SF_NOTIFY_SEND_RESPONSE
// SF_NOTIFY_SEND_RAW_DATA
// SF_NOTIFY_END_OF_REQUEST
// SF_NOTIFY_LOG            -- IIRF potentially logs things here. 
// SF_NOTIFY_LOG
// SF_NOTIFY_END_OF_NET_SESSION



/* extern "C" */
DWORD WINAPI 
HttpFilterProc(
    HTTP_FILTER_CONTEXT *      pfc,
    DWORD                      dwNotificationType,
    VOID *                     pvNotification
    )
{

    switch ( dwNotificationType ) {
#if 0
        case SF_NOTIFY_PREPROC_HEADERS:
            LogMessage(3, "HttpFilterProc: SF_NOTIFY_PREPROC_HEADERS");
            return OnPreprocHeaders(pfc,
                                    (HTTP_FILTER_PREPROC_HEADERS *) pvNotification );
            break;
#endif

        case SF_NOTIFY_URL_MAP:
            LogMessage(3, "HttpFilterProc: SF_NOTIFY_URL_MAP");
            return OnUrlMap(pfc,
                            (HTTP_FILTER_URL_MAP *) pvNotification );
            break;

        case SF_NOTIFY_AUTH_COMPLETE:
            LogMessage(3, "HttpFilterProc: SF_NOTIFY_AUTH_COMPLETE");
            return OnAuthComplete(pfc,
                                  (HTTP_FILTER_AUTH_COMPLETE_INFO *) pvNotification );
            break;

        case SF_NOTIFY_LOG:
            LogMessage(3, "HttpFilterProc: SF_NOTIFY_LOG");
            return OnLog(pfc,
                         (HTTP_FILTER_LOG *) pvNotification );
            break;
        default: 
            LogMessage(3, "HttpFilterProc: notification type: (%d)",dwNotificationType); 
            break;
    }

    return SF_STATUS_REQ_NEXT_NOTIFICATION;
}





BOOL WINAPI TerminateFilter(DWORD dwFlags) {
    /* free / unload / unlock any allocated/loaded/locked resources */

    TerminateWatch= TRUE; 

    LogMessage(0, "TerminateFilter");
    return TRUE;
}



static HINSTANCE g_hInstance = NULL;

HINSTANCE __stdcall AfxGetResourceHandle()
{ 
    return g_hInstance;
}




/*
 * Set gIirfVersion string to a meaningful string.
 *
 * something like:
 *
 * Ionic ISAPI Rewriting Filter (IIRF) 2.0.1.1003 DEBUG
 *
 */
void SetVersionInfo(char * ModuleFullpath)
{
    ULONGLONG fileVersion = 0;
    VS_FIXEDFILEINFO *fInfo = NULL;
    DWORD dwHandle;
    // get the version number of the DLL
    DWORD dwSize = GetFileVersionInfoSizeA(ModuleFullpath, &dwHandle);
    if (dwSize > 0)
    {
        LPVOID vData = malloc(dwSize);
        if (vData != NULL)
        {
            if (GetFileVersionInfoA(ModuleFullpath, dwHandle, dwSize, vData) != 0)
            {
                UINT len;
                TCHAR szSubBlock[] = _T("\\");
                if (VerQueryValue(vData, szSubBlock, (LPVOID*) &fInfo, &len) == 0)
                    fInfo = NULL;
                else
                {
                    fileVersion = ((ULONGLONG)fInfo->dwFileVersionLS) + ((ULONGLONG)fInfo->dwFileVersionMS << 32);
                }
            }
            free(vData);
        }
    }

    if (fileVersion == 0)
    {
        int len= _scprintf("%s 0.0.0.0 %s",
                           IIRF_FILTER_NAME,
                           buildFlavor) + 1;
        gIirfVersion = malloc(sizeof(char) * len);
        sprintf_s(gIirfVersion, len, "%s 0.0.0.0 %s",
                  IIRF_FILTER_NAME,
                  buildFlavor);
    }
    else
    {
        DWORD v4 = (DWORD) fileVersion & 0xFFFF;
        DWORD v3 = (DWORD) (fileVersion>>16) & 0xFFFF;
        DWORD v2 = (DWORD) (fileVersion>>32) & 0xFFFF;
        DWORD v1 = (DWORD) (fileVersion>>48) & 0xFFFF;
        int len= _scprintf("%s %d.%d.%d.%d %s",
                           IIRF_FILTER_NAME,
                           v1, v2, v3, v4,
                           buildFlavor) + 1;
        gIirfVersion = malloc(sizeof(char) * len);
        sprintf_s(gIirfVersion, len, "%s %d.%d.%d.%d %s",
                  IIRF_FILTER_NAME,
                  v1, v2, v3, v4,
                  buildFlavor);
    }
}





BOOL WINAPI DllMain(HINSTANCE hInst, ULONG ulReason, LPVOID lpReserved) 
{
    //char szLastAd[4];
    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    char ModuleFullpath[_MAX_PATH];

    boolean retVal= FALSE;

    switch( ulReason ) {

        case DLL_PROCESS_ATTACH: 
            // on process attach we can initialize the state of the filter. 
        {
            char ProgramFname[_MAX_PATH];
            char Extension[_MAX_PATH];
            char ProgramName[_MAX_PATH];
            char *TestProgramName1= "TestDriver.exe";
            char *TestProgramName2= "TestParse.exe";
            char *TestProgramName3= "IirfVersion.exe";
            char *VersionProgramName= "IirfVersion.exe";

            //printf("DllMain PROCESS_ATTACH\n"); 
                
            InitializeCriticalSection(&g_CS);
            InitializeCriticalSection(&g_CS_Logfile);

            // http://www.codeplex.com/IIRF/WorkItem/View.aspx?WorkItemId=17002
            // set handle for *_s secure string handling - invalid params.
            // see http://msdn.microsoft.com/en-us/library/a9yf33zb.aspx
            _set_invalid_parameter_handler( myInvalidParameterHandler );
            
            // Disable the message box for assertions. (like "buffer too small")
            _CrtSetReportMode(_CRT_ASSERT, 0);

            if (GetModuleFileName(hInst, ModuleFullpath, sizeof(ModuleFullpath))) 
            {
                _splitpath_s(ModuleFullpath, drive, _MAX_DRIVE, dir, _MAX_DIR, ModuleFname, _MAX_FNAME, NULL, 0);
                _makepath_s(IniFileName, _MAX_PATH, drive, dir, ModuleFname, ".ini");
                _makepath_s(IniFileDirectory, _MAX_PATH, drive, dir, NULL, NULL);
                LogMessage(1,"target ini file: '%s'", IniFileName);
                retVal= TRUE;
            }
            else 
                LogMessage(1, "Cannot get module name??");

            SetVersionInfo(ModuleFullpath);
            
            // Here we need to check whether the DLL is running in testdriver.EXE, and not within the context
            // of a webserver (eg, inetinfo.exe on IIS5 or w3wp.exe on IIS6.  
            // _pgmptr is a global variable that stores the full path of the executable image name, but it is 
            // deprecated in VC8, so we use the _get_pgmptr() routine instead. 
            _get_pgmptr(&MyFullProgramName);
            _splitpath_s(MyFullProgramName, drive, _MAX_DRIVE, dir, _MAX_DIR, ProgramFname, _MAX_FNAME, Extension, _MAX_PATH);
            sprintf_s(ProgramName, _MAX_PATH, "%s%s", ProgramFname, Extension);

            if (_strnicmp(ProgramName, VersionProgramName, strlen(VersionProgramName))==0) {
                // do nothing! 
                gTesting= TRUE; 
                retVal= TRUE; 
            }
            
            else if ((_strnicmp(ProgramName, TestProgramName1, strlen(TestProgramName1))==0) ||
                     (_strnicmp(ProgramName, TestProgramName2, strlen(TestProgramName2))==0) ||
                     (_strnicmp(ProgramName, TestProgramName3, strlen(TestProgramName3))==0)) {
                // we are in a test program, do not initialize
                gTesting= TRUE; 
                retVal= TRUE; 
            }
            else {
                // actual use as a filter, as well as IirfVersion.exe
                if ( ! FilterInitialized ) {
                    Initialize();
                }
            }
            break;
        }


        case DLL_THREAD_DETACH:
            //LogMessage(1, "DllMain THREAD_DETACH");
            break;

        case DLL_PROCESS_DETACH:
            if (gAlreadyCleanedUp) break;
            if (gIirfVersion)
            {
                free(gIirfVersion);
                gIirfVersion = NULL;
            }
            LogMessage(1, "DllMain PROCESS_DETACH");

            if (!gTesting)
                AwaitWatcherTermination();

            DeleteCriticalSection(&g_CS);
            DeleteCriticalSection(&g_CS_Logfile);
            gAlreadyCleanedUp= TRUE; 
            break;

    }
    return retVal;
}



// util routines
void EmitCachedMessages()
{
    if (MsgCache) {
        // emit cached messages
        CachedLogMessage * currentMsg;
        CachedLogMessage * previousMsg;

        currentMsg = MsgCache;
        while (currentMsg != NULL) {
            LogMessage(1, "Cached: %s", currentMsg->Data);
            previousMsg = currentMsg;
            currentMsg= currentMsg->Next;
            // clean up as we go
            free(previousMsg->Data);
            free(previousMsg);
        }
        MsgCache= NULL;
    }
}


void CacheLogMessage( char * format, ... )
{
    va_list args;
    CachedLogMessage * Msg = (CachedLogMessage *) malloc(sizeof(CachedLogMessage));
    int len;
    va_start( args, format );
    len = _vscprintf( format, args ) + 1; // _vscprintf doesn't count terminating '\0'
    Msg->Data= malloc( len * sizeof(char) );
    vsprintf_s( Msg->Data, len, format, args );
    Msg->Next = NULL;

    // cache it: 
    if (MsgCache==NULL) 
        MsgCache= Msg;
    else {
        CachedLogMessage * c= MsgCache;
        while (c->Next != NULL) c= c->Next;
        c->Next = Msg;
    }
}


 char * logFormat = "%s - %5d - %s\n";
 char * logFormat_NoNewline = "%s - %5d - %s";

void LogMessage( int MsgLevel, char * format, ... )
{
    time_t t;
    char TimeBuffer[26] ;
    va_list args;
    int len;
    char * MessageBuffer;
    int r = -1;
    char *format1;
    
    EnterCriticalSection(&g_CS_Logfile);

    // If there's no logfile yet, we automatically produce the message,
    // assuming that we just haven't gotten to the right spot in the ini file
    // to set the log file.  We also produce the message if there IS a logfile
    // (which implies config is non-null), and if the loglevel is appropriate. 
    if (g_LogFp==NULL || config->LogLevel >= MsgLevel ) { 
        va_start( args, format );
        len = _vscprintf( format, args ) + 1; // _vscprintf doesn't count terminating '\0'
        MessageBuffer = malloc( len * sizeof(char) );
        r= vsprintf_s( MessageBuffer, len, format, args );

        // At this point, we have generated the message.
        
        // non-null logfile implies that the config is non-null and the level is appropriate.
        if (g_LogFp!=NULL) {
            if (config->FirstLog) {
                config->FirstLog=FALSE;
                fprintf(g_LogFp,"\n--------------------------------------------\n");
                LogMessage(1, "Initialize: %s", gIirfVersion);
                LogMessage(1, "IIRF Built on: %s", gIirfBuildSig);
                LogMessage(1, "Initialize: config file '%s'", IniFileName);
                EmitCachedMessages();
                fflush(g_LogFp);
            }

            time(&t);
            ctime_s(TimeBuffer,26,&t);
            // 0123456789012345678901234 5 
            // Wed Jan 02 02:03:55 1980\n\0
            TimeBuffer[19]=0; // terminate before year and newline
            format1 = (MessageBuffer[len-2]=='\n')?logFormat_NoNewline : logFormat;
            fprintf(g_LogFp, format1, TimeBuffer, GetCurrentThreadId(), (r!=-1)?MessageBuffer:format);
            fflush(g_LogFp);
        }
        else if (!config || config->LogLevel >= MsgLevel ) {
            // Cache the log message if no config yet, or if we have a config, and
            // the config level is appropriate.
            if (r!=-1)
                CacheLogMessage("%s", MessageBuffer);
            else
                CacheLogMessage("%s", format);
        }
        
        free( MessageBuffer );
    }

    LeaveCriticalSection(&g_CS_Logfile);
    
}



int cyclesWithNoChanges= 0; 
void AwaitIniChangeAndReinit(DWORD notifyFlags)
{
    FILE_NOTIFY_INFORMATION Buffer[24];
    DWORD BytesReturned;
    BOOL anyChanges;
    char shortname[_MAX_PATH];
    char ext[_MAX_PATH];

    if (cyclesWithNoChanges == 0)
        LogMessage(5, "AwaitIniChangeAndReinit()...");

    _splitpath_s(IniFileName, NULL, 0, NULL, 0, shortname, _MAX_PATH, ext, _MAX_PATH);
    strcat_s(shortname, _MAX_PATH, ext);

    anyChanges= ReadDirectoryChangesW( g_hDir,
                                       &Buffer, 
                                       sizeof(Buffer), 
                                       FALSE,          // watch subtree
                                       notifyFlags, 
                                       &BytesReturned,  
                                       NULL,           // overlapped structure (for async notification)
                                       NULL);          // IO completion routine

    if (TerminateWatch) {
        LogMessage(5,"AwaitIniChangeAndReinit: Pre-empted...");
        return;
    }

    if (anyChanges) {
        FILE_NOTIFY_INFORMATION * pInfo = (FILE_NOTIFY_INFORMATION *) Buffer;
        BOOL ChangeDetected= FALSE;
        
        LogMessage (5, "AwaitIniChangeAndReinit: watcher got something after %d cycles of no changes...",
                    cyclesWithNoChanges);
        
        cyclesWithNoChanges = 0; 

        while (pInfo!=NULL) {
            DWORD action = pInfo->Action;
            wchar_t wszNameOfChangedFile[_MAX_PATH] ;
            char szName[_MAX_PATH]; 

            // pInfo->Filename is not null terminated. Copy the characters and null terminate the string.
            // pInfo->FileNameLength is length in bytes, not wchar_t.  So it is 14 for L"foo.ini" . 
            if (pInfo->FileNameLength / sizeof(wchar_t) < _MAX_PATH ) { 
                wcsncpy_s(wszNameOfChangedFile, _MAX_PATH, pInfo->FileName, pInfo->FileNameLength/sizeof(wchar_t));
                wszNameOfChangedFile[pInfo->FileNameLength/sizeof(wchar_t)]=L'\0';

                if (0 != WideCharToMultiByte((UINT) CP_ACP,                      // code page
                                             (DWORD) 0,                          // conversion flags
                                             (LPCWSTR) wszNameOfChangedFile,     // wchar string to convert
                                             (int) wcslen(wszNameOfChangedFile), // number of chars in string.
                                             (LPSTR) szName,                     // buffer for new string
                                             sizeof(szName)/sizeof(szName[0]),   // size of buffer
                                             (LPCSTR) "!",                       // default for unmappable chars
                                             (LPBOOL) NULL                       // set when default char used
                        )) {

                    szName[pInfo->FileNameLength/sizeof(wchar_t)]='\0';

                    LogMessage(5,"AwaitIniChangeAndReinit: Detected change in file '%s'", szName);


                    if (_strnicmp(shortname, szName, strlen(shortname))==0) {
                        // change in ini file detected 
                        IirfConfig * newconfig, * oldconfig;
                        LogMessage(1, "AwaitIniChangeAndReinit: Detected change in the  ini file '%s'", IniFileName);
                        LogMessage(1, "AwaitIniChangeAndReinit: %s", gIirfVersion);

                        Sleep(120); // attempt to avoid the race condition where the file is not ready...

                        // read new config info from the ini file.  
                        // this includes the log level, the log file, other settings, and all the rules. 
                        newconfig= ReadConfig(IniFileName, 0);

                        if (newconfig==NULL) {  
                            // In some cases, the file is not ready to be read, and we get zero lines. 
                            // in those cases, we just DONT use the config, and loop around, waiting for
                            // more changes.  If we get another change notification, we then attempt to 
                            // read the file again.

                            LogMessage(1,"AwaitIniChangeAndReinit: ini file not ready to be read? ... reverting to previous confg...");
                        }
                        else {
                            // here is where we actually switchover the configuration (metadata). 
                            // NB: {Enter,Leave}CriticalSection provides an in-process mutex
                            
                            EnterCriticalSection(&g_CS);
                            oldconfig= config;
                            config= newconfig;
                            OpenLogfile();
                            LeaveCriticalSection(&g_CS);
                            if (newconfig->rootRule == NULL) {
                                // rootRule == NULL  when the file is successfully read, but when
                                // there are no rules at all in the file, which is a valid configuration.
                                LogMessage(1,"AwaitIniChangeAndReinit: INFO: Zero rules found in the INI file. ");
                            }

                            ReleaseConfig(oldconfig);
                        }


                        ChangeDetected= TRUE; 
                    }
                }
            }

            LogMessage(5,"AwaitIniChangeAndReinit:  TerminateWatch = %s", TerminateWatch?"TRUE":"FALSE"); 

            if (TerminateWatch) {
                LogMessage(1,"AwaitIniChangeAndReinit: Watcher is terminating....");
                pInfo= NULL;
            }
            else {
                if ((!ChangeDetected) && (pInfo->NextEntryOffset > 0)) {
                    // we did not get a change in the ini file, and there are more records returned. 
                    // so we will check the next change buffer . 
                    pInfo = (FILE_NOTIFY_INFORMATION *)
                        (((CHAR *) pInfo) + pInfo->NextEntryOffset);  // maybe NULL
                }
                else
                    pInfo = NULL;  // stop checking for more changes
            }

        }

    }
    else
    {
        if (cyclesWithNoChanges == 0)
            LogMessage(5,"AwaitIniChangeAndReinit: no changes found.");
        cyclesWithNoChanges++;

        if (cyclesWithNoChanges > 500)
        {
            // warn and terminate.
            LogMessage(0, "ERROR: Too many change notifications. Move the log file to a different directory.  See the Readme for more info.");
            exit(1);
        }
    }
}


///
/// Entry point for the thread that watches for changes in the ini file. 
///
DWORD WINAPI FileChangeWatcher(LPVOID lpParam)  
{
    char * directoryPathName= (char*) lpParam;
    DWORD notifyFlags= FILE_NOTIFY_CHANGE_LAST_WRITE;

    LogMessage(4,"FileChangeWatcher(): Enter");

    // Open the directory;  need the handle for ReadDirectoryChangesW
    g_hDir = CreateFile( directoryPathName, // directory path
                         FILE_LIST_DIRECTORY, 
                         FILE_SHARE_READ|FILE_SHARE_DELETE,  
                         NULL, 
                         OPEN_EXISTING,                      // open but dont create
                         FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, // need overlapped to allow async close on g_hDir
                         NULL 
        );

    while (!TerminateWatch) {
        LogMessage(4,"FileChangeWatcher: Await()...");
        AwaitIniChangeAndReinit(notifyFlags);
        LogMessage(4,"FileChangeWatcher(): Await returns (TerminateWatch= %s)", TerminateWatch?"TRUE":"FALSE");
    }
    
    // no need to close handle.  It is closed in the DllMain PROCESS_DETACH logic

    LogMessage(4,"FileChangeWatcher: return()...");

    WatcherDone= TRUE; 

    return (0);     //calls ExitThread(x) implicitly
}




void AwaitWatcherTermination() 
{
    DWORD threadExitCode=0;
    int period= 150; // in milliseconds
    int timeSlept = 0;
    int i;
    BOOL terminated= FALSE;

    LogMessage(2,"AwaitWatcherTermination: closing dir handle.");

    TerminateWatch= TRUE; 
    if (g_hDir) {
        // Closing this handle will signal ReadDirectoryChangesW, which will wake the watcher thread. 
        // when the watcher thread awakes, it will see that TerminateWatch is TRUE, and will exit. 
        CloseHandle( g_hDir ); 
        g_hDir= NULL;

        // Closing the dir handle may or may not be necessary, because on shutdown of
        // inetinfo.exe, the metabase.bin changes, and it causes ReadDirectoryChangesW to
        // return.  But the same may not be true on w3svc.exe (IIS6). 
    }

    // Here, wait for the watcher thread to exit.  I tried waiting for the thread exit status, but that did not work,
    // I always got STILL_ACTIVE.  Maybe that is due to the particular environment, like a thread operating
    // within a DLL on PROCESS_DETACH.  Not sure.  In any case, I resorted to a manual flag (WatcherDone) which
    // FileChangeWatcher() sets just before returning.

    for (i=1; !WatcherDone; i++) {
        LogMessage(3,"AwaitWatcherTermination: Waiting %d ms ...", period);

        Sleep(period);
        // workitem 21578
        timeSlept += period;
        if (timeSlept > 30000) break;
        if ((i % 4) == 0) period *= 2;
    }

    if (hWatcherThread) {
        CloseHandle( hWatcherThread );
        hWatcherThread= NULL;
    }

    // workitem 21578
    if (WatcherDone)
        LogMessage(1,"AwaitWatcherTermination: watcher thread is terminated...");
    else
        LogMessage(1,"AwaitWatcherTermination: terminating after timeout...");
}




void Initialize() 
{
    EnterCriticalSection(&g_CS);
    if ( ! FilterInitialized ) {
        DWORD ThreadId; 
        LPVOID pData; 

        config= ReadConfig(IniFileName,0);
        
        // work item 11707
        if (config==NULL) {
            // there's no config file.  We're going into "sulk mode", which means the filter
            // initializes, but does not do anything. It doesn't even look for changes in the
            // ini file. 
            config= malloc(sizeof(IirfConfig)); 
            config->rootRule= NULL;
            config->LogLevel= DEFAULT_LOG_LEVEL;
            config->LogFileName[0]= '\0';
            config->FilterPriority= SF_NOTIFY_ORDER_DEFAULT ;
            config->IterationLimit= ITERATION_LIMIT_DEFAULT;
            config->MaxMatchCount= MAX_MATCH_COUNT_DEFAULT;
            config->WantNotifyLog= FALSE;
            config->FirstLog= TRUE;
            // don't try to read the config again.
            FilterInitialized= TRUE;    

            goto Done_Initialize;
        }

        //config->FirstLog= TRUE;
        
        if (!gTesting) {
            pData= IniFileDirectory; 

            // create thread to watch ini file for changes, so we can re-initialize
            hWatcherThread = CreateThread( NULL,              // default security attributes
                                           0,                 // use default stack size  
                                           FileChangeWatcher,  // thread function 
                                           pData,             // argument to thread function 
                                           0,                 // use default creation flags 
                                           &ThreadId);   // returns the thread identifier 


            if ( !hWatcherThread ) 
                LogMessage(0,"Initialize: Cannot create file-watcher thread. Changes to ini file will not be autoloaded.");
            else 
                LogMessage(1,"Initialize: File watcher thread created.");
            
        }
        FilterInitialized= TRUE;    
    }

Done_Initialize:
    LeaveCriticalSection(&g_CS);
}


//
// Open the log file 
//
void OpenLogfile() 
{
    BOOL reopen= FALSE;
    EnterCriticalSection(&g_CS_Logfile);
    
    if (g_LogFp!=NULL) {
        fclose(g_LogFp);
        reopen= TRUE;
        g_LogFp= NULL;
    }

#ifdef DIAGNOSTIC
    g_LogFp= _fsopen("c:\\temp\\IIRF.log","w", _SH_DENYWR );
#else    
    if ((config!=NULL) && (config->LogFileName!= NULL) && (config->LogFileName[0]!='\0')) {
        //fopen_s(&g_LogFp, (gTesting) ? "CON":config->LogFileName,"a+");
        g_LogFp= _fsopen((gTesting) ? "CON":config->LogFileName,"a", _SH_DENYWR );

        if (g_LogFp==NULL) 
            //fopen_s(&g_LogFp, (gTesting) ? "CON":config->LogFileName,"w");
            g_LogFp= _fsopen((gTesting) ? "CON":config->LogFileName,"w", _SH_DENYWR );
    }
#endif
    
    LeaveCriticalSection(&g_CS_Logfile);
    LogMessage(1,(reopen)?"LogFile re-opened.": "New LogFile opened.");
}



boolean ConditionsAreIdentical(RewriteCondition *c1, RewriteCondition *c2)
{
    // if both are NULL, then yes, they are identical
    if ((c1 == NULL) && (c2== NULL)) 
        return TRUE; 

    // if only one of them is NULL, then NO they are not identical
    if (c1 == NULL) return FALSE;
    if (c2 == NULL) return FALSE;

    // otherwise, if any of the properties differ, then NO they are not identical
    if ((c1->TestString != NULL) && (c2->TestString!= NULL) && 
        (strcmp(c1->TestString, c2->TestString)==0) &&
        (c1->IsCaseInsensitive == c2->IsCaseInsensitive) &&
        (c1->Pattern != NULL) && (c2->Pattern != NULL) &&
        (strcmp(c1->Pattern, c2->Pattern)==0) &&
        (c1->LogicalOperator == c2->LogicalOperator)
        ) 
        // otherwise, compare the children.  
        return ConditionsAreIdentical(c1->Child, c2->Child);

    return FALSE;
}


boolean IsDuplicateRule(RewriteRule * root, char * pattern,  char * header, RewriteCondition * cond) 
{
    RewriteRule * current= root;

    while (current!=NULL) {
        if (
            ( ((header == NULL) && (current->HeaderToRewrite == NULL)) ||    // both headers null OR headers identical
              ((header != NULL) && (current->HeaderToRewrite != NULL) && (strcmp(current->HeaderToRewrite, header)==0)) ) && // AND
            (strcmp(current->Pattern, pattern)==0) &&   // patterns are identical , AND
            ConditionsAreIdentical(cond, current->Condition)  // conditions are identical
            ) {
            return TRUE; 
        }

        current= current->next; // go to the next rule in the list
    }
    return FALSE;
}



void InsertCond(RewriteCondition ** root, RewriteCondition * newCond)
{
    if ((*root)==NULL) {
        *root= newCond;
        return;
    }
    
    InsertCond( &((*root)->Child), newCond);
    return;
}



void CheckForSpecialCondition(char * pattern, RewriteCondition *cond)
{
    char * p1= pattern; 
    int ix= 0;
    cond->SpecialConditionType= '\0';  // null character implies "no special condition"
    cond->IsSpecialNegated= FALSE;

    if (p1[ix] == '!') {
        cond->IsSpecialNegated= TRUE;
        ix++;
    }

    if ((p1[ix] == '-') && ((p1[ix+1]=='d') || (p1[ix+1]=='f')))
        cond->SpecialConditionType= p1[ix+1];

    return;
}


char * PriorityToString(DWORD FilterPriority)
{
    if (FilterPriority==SF_NOTIFY_ORDER_HIGH) return "HIGH";
    if (FilterPriority==SF_NOTIFY_ORDER_MEDIUM) return "MEDIUM";
    if (FilterPriority==SF_NOTIFY_ORDER_LOW) return "LOW";
    return "Unknown";
}


#define RE_SIZE 1024

/* EXPORT - for testing only*/
IirfConfig * ReadConfig(char * ConfigFile, int retryCount) 
{
    IirfConfig * thisConfig= malloc(sizeof(IirfConfig)); 
    const char *error;
    int erroffset;
    BOOL done= FALSE;
    BOOL SuccessfulRead= FALSE;
    BOOL LogFileHasBeenSet= FALSE;
    FILE *infile ;
    unsigned char *p1;
    unsigned char *p2;
    pcre * re;
    RewriteRule * currentRule= NULL;
    RewriteRule * previousRule;
    RewriteCondition * currentCond= NULL;
    int lineNum=0; 
    unsigned int lineLength;
    char delims[]= " \n\r\t";
    char * StrtokContext= NULL;

    unsigned char * buffer;

    //printf("ReadConfig\n"); 

    // bootstrap:  if this is initial config, use it while processing the ini file. 

    // When it is not the initial read of config, in other words, on config updates
    // because of an ini file change, we change the config atomically, after
    // reading everything. 
    if (config==NULL) config= thisConfig; 

    if (gTesting) {
        // force logging to console
        strcpy_s(thisConfig->LogFileName, sizeof(thisConfig->LogFileName)/sizeof(thisConfig->LogFileName[0]), "CON"); 
        thisConfig->LogLevel=0; 
        OpenLogfile();
    }

    LogMessage(1, "ReadConfig");

    buffer = (unsigned char *) malloc(RE_SIZE);
    if (buffer==NULL)
    {
        free(thisConfig);
        return NULL;
    }

    thisConfig->rootRule= NULL;
    thisConfig->StatusUrl= NULL;
    thisConfig->AllowRemoteStatus= FALSE;
    thisConfig->LogLevel= DEFAULT_LOG_LEVEL;
    thisConfig->WantNotifyLog= FALSE;
    thisConfig->EngineOff= FALSE;
    thisConfig->StrictParsing= STRICT_PARSING_DEFAULT;
    thisConfig->FirstLog= TRUE;
    thisConfig->FilterPriority= SF_NOTIFY_ORDER_DEFAULT ;
    thisConfig->IterationLimit= ITERATION_LIMIT_DEFAULT;
    thisConfig->MaxMatchCount= MAX_MATCH_COUNT_DEFAULT;
    thisConfig->CondSubstringBackrefFlag= '%';
    thisConfig->numRequestsServed= 0;
    thisConfig->nErrors= 0;
    thisConfig->nRules= 0;
    thisConfig->nLines= 0;
    thisConfig->nWarnings= 0;
    if (!gTesting) thisConfig->LogFileName[0]='\0';

    // get timestamp of the file
    GetLastUpdate(ConfigFile, &(thisConfig->LastWriteOfIniFile));

    // get the time RIGHT NOW
    GetSystemTime(&(thisConfig->ConfigRead));
    
    /* read config file here, slurping in Rewrite rules */ 

    // errorNumber= fopen_s(&infile, ConfigFile, "r");
#pragma warning( suppress : 4996 )
    infile= fopen(ConfigFile, "r");  /// don't want fopen_s(), because that function opens in exclusive mode
    if (infile==NULL) {
        LogMessage(1, "ReadConfig: Could not open config file '%s' (error: %d)", ConfigFile, GetLastError());
        thisConfig->StatusUrl = _strdup("/iirfStatus");
        return thisConfig;  // bunch of default settings.
    }

    
    //printf("reading config...(%s)\n", ConfigFile); 
    while (!done) {
        lineNum++;
        if (fgets((char *)buffer, RE_SIZE, infile) == NULL) break;

        SuccessfulRead= TRUE;

        p1 = buffer;
        while (isspace(*p1)) p1++;
        if (*p1 == 0) continue; // nothing
        if (*p1 == '#') continue; // comment

        // http://www.codeplex.com/IIRF/WorkItem/View.aspx?WorkItemId=9856
        lineLength= strlen(p1);
        p2= strtok_s(p1, " \t", &StrtokContext);  // split by spaces or TAB
        if ((_strnicmp(p2,DIRECTIVE_REWRITE_RULE, strlen(DIRECTIVE_REWRITE_RULE))==0) ||
            (_strnicmp(p2,DIRECTIVE_REDIRECT_RULE, strlen(DIRECTIVE_REDIRECT_RULE))==0) ||
            (_strnicmp(p2,DIRECTIVE_REWRITE_HEADER, strlen(DIRECTIVE_REWRITE_HEADER))==0)) {
            char *pHeaderToRewrite= NULL;
            char *pPattern ;
            char *pReplacement;
            char *pModifiers;
            char *directive;
            int PcreOptions= 0;
            int rc=0;

            if ((_strnicmp(p2,DIRECTIVE_REWRITE_RULE, strlen(DIRECTIVE_REWRITE_RULE))==0) ||
                (_strnicmp(p2,DIRECTIVE_REDIRECT_RULE, strlen(DIRECTIVE_REDIRECT_RULE))==0)) {
                // (RewriteRule|RedirectRule) Pattern Replacement ModiferFlags
                pPattern = strtok_s(NULL, delims, &StrtokContext);
                pReplacement = strtok_s(NULL, delims, &StrtokContext);
                pModifiers = strtok_s(NULL, delims, &StrtokContext);
                directive = (_strnicmp(p2,DIRECTIVE_REWRITE_RULE, strlen(DIRECTIVE_REWRITE_RULE))==0) ?
                    DIRECTIVE_REWRITE_RULE :  DIRECTIVE_REDIRECT_RULE;

                LogMessage(1, "ReadConfig: line %3d: %s (rule %d)  '%s'  '%s' %8s", 
                           lineNum, directive, thisConfig->nRules+1, pPattern, pReplacement,  pModifiers );

            }
            else {
                // RewriteHeader Header Pattern Replacement ModiferFlags
                pHeaderToRewrite = strtok_s(NULL, delims, &StrtokContext);
                pPattern = strtok_s(NULL, delims, &StrtokContext);
                pReplacement = strtok_s(NULL, delims, &StrtokContext);
                pModifiers = strtok_s(NULL, delims, &StrtokContext);
                directive = DIRECTIVE_REWRITE_HEADER;
                LogMessage(1, "ReadConfig: line %3d: RewriteHeader (rule %d)  '%s'  '%s'  '%s' %8s", 
                           lineNum, thisConfig->nRules+1, pHeaderToRewrite, pPattern, pReplacement,  pModifiers );

                // no need to be rigid! 
                //if ((pHeaderToRewrite == NULL) || (pHeaderToRewrite[strlen(pHeaderToRewrite)-1] != ':')) {
                //    LogMessage(1, "ReadConfig: ERROR: Header must end in a colon.  Ignoring this directive.");
                //    nErrors++;
                //    continue; 
                //}
            }

            // check for bad format
            if ((pPattern == NULL) || (pReplacement==NULL)) {
                LogMessage(1, "ReadConfig: ERROR: line %d: bad rule format", lineNum);
                thisConfig->nErrors++;
                continue; 
            }
            
            // check for duplicates
            if (IsDuplicateRule(thisConfig->rootRule, pPattern, pHeaderToRewrite, currentCond)) {
                LogMessage(1, "ReadConfig: ERROR: line %d: duplicate rule '%s'", lineNum, pPattern);
                thisConfig->nErrors++;
                continue; 
            }
            
            LogMessage(5,"ReadConfig: not a duplicate rule..."); 

            previousRule= currentRule;  // for the first rule, this is NULL.

            currentRule= (RewriteRule *) malloc(sizeof(RewriteRule)); 
            if (thisConfig->rootRule==NULL) thisConfig->rootRule= currentRule; 

            if (pHeaderToRewrite != NULL) {
                // keep any trailing colon, or add one if necessary.
                // (it is required for SetHeader() later)
                int len = strlen(pHeaderToRewrite);
                if (pHeaderToRewrite[strlen(pHeaderToRewrite)-1] != ':')
                {
                    // we need a colon
                    currentRule->HeaderToRewrite= (char*) malloc(len+2); 
                    strcpy_s(currentRule->HeaderToRewrite, len+1, pHeaderToRewrite);
                    currentRule->HeaderToRewrite[len]=':';
                    currentRule->HeaderToRewrite[len+1]='\0';
                }
                else
                {
                    // there is a colon
                    currentRule->HeaderToRewrite= (char*) malloc(len+1); 
                    strcpy_s(currentRule->HeaderToRewrite, len+1, pHeaderToRewrite);
                }
            }
            else currentRule->HeaderToRewrite= NULL;

            currentRule->Pattern= (char*) malloc(strlen(pPattern)+1); 
            strcpy_s(currentRule->Pattern, strlen(pPattern)+1, pPattern);
            currentRule->Replacement= (char*) malloc(strlen(pReplacement)+1); 
            strcpy_s(currentRule->Replacement, strlen(pReplacement)+1, pReplacement);

            currentRule->Condition= currentCond; 
            currentCond= NULL;  // this cond has been used, so forget it.
            currentRule->RE= NULL; // initialize in case we call FreeRuleList()
            currentRule->next= NULL;
            currentRule->IsRedirect= (_strnicmp(directive,DIRECTIVE_REDIRECT_RULE, strlen(DIRECTIVE_REDIRECT_RULE))==0);
            currentRule->RedirectCode= 302;
            // parse and apply rule modifier flags 
            rc= ParseRuleModifierFlags(thisConfig, directive, pModifiers, currentRule);
            if (rc)
            {
                if (rc==-1)
                    LogMessage(1, "ReadConfig: ERROR: line %d: DO NOT USE [R] with RewriteRule - use RedirectRule instead!", lineNum);
                else
                    LogMessage(1, "ReadConfig: ERROR: line %d: invalid modifiers, Ignoring that rule.", lineNum);

                thisConfig->nErrors++;
                // unwind
                FreeRuleList(currentRule);

                if (thisConfig->rootRule==currentRule) 
                    thisConfig->rootRule= NULL; 

                currentRule= previousRule;  
                continue;
            }


            // check if http{s}:// for rewrite
            if ( _strnicmp(p2,DIRECTIVE_REWRITE_RULE, strlen(DIRECTIVE_REWRITE_RULE))==0  &&
                 (_strnicmp(pReplacement,"http://", strlen("http://"))==0  ||
                  _strnicmp(pReplacement,"https://", strlen("https://"))==0 ) &&
                 ! currentRule->IsRedirect ) {
                    
                LogMessage(1, "ReadConfig: WARNING: Rewriting to a fully-qualified URL. Do you want REDIRECT?");
                thisConfig->nWarnings++;
            }

            // check if NOT http{s}:// for redirect
            else if ( _strnicmp(p2,DIRECTIVE_REDIRECT_RULE, strlen(DIRECTIVE_REDIRECT_RULE))==0  &&
                      (_strnicmp(pReplacement,"http://", strlen("http://"))!=0  &&
                       _strnicmp(pReplacement,"https://", strlen("https://"))!=0 )) {

                LogMessage(1, "ReadConfig: NOTE: Redirecting target is local - does not include an http(s):// scheme.");
            }


            if (currentRule->RecordOriginalUrl) thisConfig->WantNotifyLog= TRUE; // later, we will register for SF_NOTIFY_LOG
            if (currentRule->IsCaseInsensitive) PcreOptions |= PCRE_CASELESS;

            // Compile the regex here, and store the result
            re = pcre_compile(pPattern,         // the pattern 
                              PcreOptions,      // options for the regex 
                              &error,           // for any error message
                              &erroffset,       // for error offset 
                              NULL);            // use default character tables 

            currentRule->RE= re; 
            thisConfig->nRules++;
            if (re == NULL) {
                LogMessage(1, "ReadConfig: ERROR: compilation of %s expression '%s' failed at offset %d: %s", 
                           directive, pPattern, erroffset, error);
                LogMessage(1, "ReadConfig: Ignoring that rule.");
                thisConfig->nErrors++;
                // unwind
                FreeRuleList(currentRule);

                if (thisConfig->rootRule==currentRule) 
                    thisConfig->rootRule= NULL; 

                currentRule= previousRule;  
                continue;
            }
            
            if (previousRule!=NULL) 
                previousRule->next= currentRule; 

        }

        else if (_strnicmp(p2,DIRECTIVE_REWRITE_COND, strlen(DIRECTIVE_REWRITE_COND))==0) {
            char *pTestString = strtok_s(NULL, delims, &StrtokContext);
            char *pPattern = strtok_s(NULL, delims, &StrtokContext);
            char *pModifiers = strtok_s(NULL, delims, &StrtokContext);
            RewriteCondition * newCond= NULL;
            int PcreOptions= 0; 

            LogMessage(1, "ReadConfig: line %3d: RewriteCond %-46s %-42s", 
                       lineNum, pTestString, pPattern );

            // check for bad format
            if ((pTestString == NULL) || (pPattern==NULL)) {
                LogMessage(1, "ReadConfig: ERROR: ini file line %d: bad cond format. Ignoring that Condition!", lineNum);
                thisConfig->nErrors++;
                continue; 
            }

            newCond= (RewriteCondition *) malloc(sizeof(RewriteCondition)); 
            newCond->Child= NULL;
            newCond->RE= NULL;
            newCond->LogicalOperator=0;

            newCond->TestString= (char*) malloc(strlen(pTestString)+1); 
            strcpy_s(newCond->TestString, strlen(pTestString)+1, pTestString);
            newCond->Pattern= (char*) malloc(strlen(pPattern)+1); 
            strcpy_s(newCond->Pattern, strlen(pPattern)+1,pPattern);

            ParseCondModifierFlags(pModifiers, newCond); 

            if (newCond->IsCaseInsensitive) PcreOptions |= PCRE_CASELESS;

            CheckForSpecialCondition(pPattern, newCond);

            if (newCond->SpecialConditionType == '\0') { 

                // pPattern does not hold a special condition (eg -f/d/s), so process the regular expression.

                re = pcre_compile(pPattern,             /* the pattern */
                                  PcreOptions,          /* the options to use when compiling the regex */
                                  &error,               /* for error message */
                                  &erroffset,           /* for error offset */
                                  NULL);                /* use default character tables */

                if (re == NULL) {
                    LogMessage(1, "ReadConfig: ERROR: compilation of RewriteCond expression '%s' failed at offset %d: %s", 
                               pPattern, erroffset, error);
                    thisConfig->nErrors++;
                    FreeCondList(newCond);
                    newCond = NULL;
                }
                else {
                    newCond->RE= re;
                }
            }

            if ((newCond != NULL) && ((newCond->RE!= NULL) || (newCond->SpecialConditionType != '\0') ) )
                InsertCond(&currentCond, newCond);
        }


        else if (_strnicmp(p2,DIRECTIVE_STRICT, strlen(DIRECTIVE_STRICT))==0) {
            char *pValue = strtok_s (NULL, delims, &StrtokContext);
            LogMessage(1, "ReadConfig: line %3d: %s %s", 
                       lineNum, DIRECTIVE_STRICT, pValue);

            if (pValue!=NULL) {
                if (_strnicmp(pValue, "ON", strlen("ON"))==0) {
                    thisConfig->StrictParsing= TRUE;
                }
                else if (_strnicmp(pValue, "OFF", strlen("OFF"))==0) {
                    thisConfig->StrictParsing= FALSE;
                }
                else {
                    LogMessage(1, "ReadConfig: WARNING: Did not find valid setting for StrictParsing (ON|OFF)" );
                    thisConfig->nWarnings++;
                }
            }
            else {
                LogMessage(1, "ReadConfig: WARNING: Did not find any (ON|OFF) value for StrictParsing");
                thisConfig->nWarnings++;
            }

            LogMessage(1, "ReadConfig: StrictParsing is now '%s'", thisConfig->StrictParsing ? "ON" : "OFF");
        }


        else if (_strnicmp(p2,DIRECTIVE_ITERATION_LIMIT, strlen(DIRECTIVE_ITERATION_LIMIT))==0) {
            char *pLimit = strtok_s(NULL, delims, &StrtokContext);
            LogMessage(1, "ReadConfig: line %d: %s %s", lineNum, DIRECTIVE_ITERATION_LIMIT, pLimit);
            if (pLimit!=NULL) {
                thisConfig->IterationLimit= atoi(pLimit); 
                // validate the value
                if (thisConfig->IterationLimit > ITERATION_LIMIT_MAX || 
                    thisConfig->IterationLimit < ITERATION_LIMIT_MIN) {
                    thisConfig->IterationLimit= ITERATION_LIMIT_DEFAULT;
                    LogMessage(1, "ReadConfig: WARNING: Out of range (%d <= x <= %d); setting Iteration Limit to the default= %d",
                               ITERATION_LIMIT_MIN, ITERATION_LIMIT_MAX, thisConfig->IterationLimit);
                    thisConfig->nWarnings++;
                }
            }
            else {
                thisConfig->IterationLimit= ITERATION_LIMIT_DEFAULT;
                LogMessage(1, "ReadConfig: WARNING: Did not find valid limit value; setting Iteration Limit to the default= %d", thisConfig->IterationLimit);
                thisConfig->nWarnings++;
            }
        }

        else if (_strnicmp(p2,DIRECTIVE_FILTER_PRIORITY, strlen(DIRECTIVE_FILTER_PRIORITY))==0) {
            if (config != thisConfig) {
                // It is not the first time reading the config.
                // In this case, we cannot update the priority. 
                // log a message to that effect and skip this stanza. 
                LogMessage(1, "ReadConfig: Not Updating Filter Priority on Ini file update.");
            }
            else {
                char *pPriority = strtok_s(NULL, delims, &StrtokContext);
                LogMessage(1, "ReadConfig: line %d: %s %s", lineNum, DIRECTIVE_FILTER_PRIORITY, pPriority);
                if (pPriority!=NULL) {
                    if (_strnicmp(pPriority, "HIGH", strlen("HIGH"))==0) {
                        thisConfig->FilterPriority= SF_NOTIFY_ORDER_HIGH ;
                    }
                    else if (_strnicmp(pPriority, "MEDIUM", strlen("MEDIUM"))==0) {
                        thisConfig->FilterPriority= SF_NOTIFY_ORDER_MEDIUM ;
                    }
                    else if (_strnicmp(pPriority, "LOW", strlen("LOW"))==0) {
                        thisConfig->FilterPriority= SF_NOTIFY_ORDER_LOW ;
                    }
                    else {
                        LogMessage(1, "ReadConfig: WARNING: Did not find valid Filter Priority Value (HIGH|MEDIUM|LOW)" );
                        thisConfig->nWarnings++;
                    }
                }
                else {
                    LogMessage(1, "ReadConfig: WARNING: Did not find any Filter Priority Value (HIGH|MEDIUM|LOW)");
                    thisConfig->nWarnings++;
                }

                LogMessage(1, "ReadConfig: Filter Priority is now: %s (0x%04x)", 
                           PriorityToString(thisConfig->FilterPriority),
                           thisConfig->FilterPriority);
            }
        }

        else if (_strnicmp(p2,DIRECTIVE_MAX_MATCH_COUNT, strlen(DIRECTIVE_MAX_MATCH_COUNT))==0) {
            char *pCount = strtok_s(NULL, delims, &StrtokContext);
            LogMessage(1, "ReadConfig: line %d: %s %s", lineNum, DIRECTIVE_MAX_MATCH_COUNT, pCount);
            if (pCount!=NULL) {
                thisConfig->MaxMatchCount= atoi(pCount);
                // validate the value
                if (thisConfig->MaxMatchCount > MAX_MATCH_COUNT_MAX || 
                    thisConfig->MaxMatchCount < MAX_MATCH_COUNT_MIN) {
                    thisConfig->MaxMatchCount= MAX_MATCH_COUNT_DEFAULT;
                    LogMessage(1, "ReadConfig: WARNING: Out of range (%d <= x <= %d); setting MaxMatchCount to the default= %d", 
                               MAX_MATCH_COUNT_MIN, MAX_MATCH_COUNT_MAX, thisConfig->MaxMatchCount);
                    thisConfig->nWarnings++;
                }
            }
            else {
                thisConfig->MaxMatchCount= MAX_MATCH_COUNT_DEFAULT;
                LogMessage(1, "ReadConfig: WARNING: MaxMatchCount value is missing. Leaving MaxMatchCount unchanged= %d", 
                           thisConfig->MaxMatchCount);
                thisConfig->nWarnings++;
            }

        }
        
        else if (_strnicmp(p2,DIRECTIVE_REWRITE_LOG_LEVEL, strlen(DIRECTIVE_REWRITE_LOG_LEVEL))==0) {
            char *pLevel = strtok_s (NULL, delims, &StrtokContext);
            LogMessage(1, "ReadConfig: line %d: %s %s", lineNum, DIRECTIVE_REWRITE_LOG_LEVEL, pLevel);
            if (pLevel!=NULL) thisConfig->LogLevel= atoi(pLevel);
            else thisConfig->LogLevel=DEFAULT_LOG_LEVEL;
            LogMessage(1, "ReadConfig: setting LogLevel to %d", thisConfig->LogLevel);
        }


        // workitem 17024
        // http://www.codeplex.com/IIRF/WorkItem/View.aspx?WorkItemId=17024
        else if (_strnicmp(p2,DIRECTIVE_COND_SUBSTRING_FLAG, strlen(DIRECTIVE_COND_SUBSTRING_FLAG))==0) {
            char *pFlag = strtok_s (NULL, delims, &StrtokContext);
            LogMessage(1, "ReadConfig: line %d: %s %s", lineNum, DIRECTIVE_COND_SUBSTRING_FLAG, pFlag);
            if (pFlag!=NULL) {
                if ( (*pFlag == '%') ||
                     (*pFlag == '@') ||
                     (*pFlag == '*') ||
                     (*pFlag == '_') ||
                     (*pFlag == '^') ||
                     (*pFlag == '!') ||
                     (*pFlag == '~')) 
                    thisConfig->CondSubstringBackrefFlag= pFlag[0];
                else {
                    thisConfig->CondSubstringBackrefFlag= COND_SUBSTRING_BACKREF_FLAG_DEFAULT;
                    LogMessage(1,"ReadConfig: WARNING: illegal CondSubstringBackrefFlag (%c); legal values are %%,@,!,~,*,_,^", pFlag[0]);
                    thisConfig->nWarnings++;
                }
            }
            else thisConfig->CondSubstringBackrefFlag= COND_SUBSTRING_BACKREF_FLAG_DEFAULT;

            LogMessage(1, "ReadConfig: setting CondSubstringBackrefFlag to '%c'", thisConfig->CondSubstringBackrefFlag);
        }

        // workitem 23459
        else if (_strnicmp(p2,DIRECTIVE_STATUS_URL, strlen(DIRECTIVE_STATUS_URL))==0) {
            char *pStatusUrl = strtok_s(NULL, delims, &StrtokContext);
            char *pRemoteOk = strtok_s(NULL, delims, &StrtokContext);
            LogMessage(1, "ReadConfig: line %d: %s %s", lineNum, DIRECTIVE_STATUS_URL, pStatusUrl);
            
            if (pStatusUrl!=NULL) {
                if (thisConfig->StatusUrl!=NULL) free(thisConfig->StatusUrl); // no leak when duplicates
                thisConfig->StatusUrl= (char*) malloc(strlen(pStatusUrl)+1); 
                strcpy_s(thisConfig->StatusUrl, strlen(pStatusUrl)+1,pStatusUrl);

                if (thisConfig->StatusUrl[0]!='/') {
                    LogMessage(1,"ReadConfig: WARNING: StatusUrl should begin with a slash (/).");
                    thisConfig->nWarnings++;
                }

                if ((pRemoteOk!=NULL) && 
                    (_strnicmp(pRemoteOk,"RemoteOk", strlen("RemoteOk"))==0)) {

                    LogMessage(1,"ReadConfig: StatusUrl is enabled for local or remote requests.");
                    thisConfig->AllowRemoteStatus= TRUE;
                }
                else
                    LogMessage(1,"ReadConfig: StatusUrl is enabled for local requests only.");
            }
        }

        // workitem 23458
        else if (_strnicmp(p2,DIRECTIVE_REWRITE_ENGINE, strlen(DIRECTIVE_REWRITE_ENGINE))==0) {
            char *pValue = p2 + strlen(p2) +1 ;
            char *p3;
            char *p4;
            p3= pValue;
            p4= pValue + strlen(pValue) - 1;
            while((*p3 == ' ')||(*p3 == '\t')) p3++;       // skip leading spaces and TABs
            while((*p4 == ' ')||(*p4 == '\n')||(*p4 == '\r')||(*p4 == '\t')) *p4--='\0'; // trim trailing spaces

            if (*pValue=='\0') {
                LogMessage(1, "ReadConfig: WARNING: line %d: you did not specify a value for RewriteEngine", lineNum);
                thisConfig->nWarnings++;
                continue; 
            }
            
            if (_strnicmp(pValue,"OFF", strlen("OFF"))==0) {
                thisConfig->EngineOff= TRUE;
                LogMessage(1, "ReadConfig: line %d: Rewriting will be disabled.");
            }
            else if (_strnicmp(pValue,"ON", strlen("ON"))!=0) {
                LogMessage(1, "ReadConfig: WARNING: line %d: unrecognized switch for RewriteEngine (%s)", pValue);
                thisConfig->nWarnings++;
                continue;
            }
        }
        

        else if (_strnicmp(p2,DIRECTIVE_REWRITE_LOG_FILE, strlen(DIRECTIVE_REWRITE_LOG_FILE))==0) {
            //char *pLogFileStub = strtok_s (NULL, delims, &StrtokContext);
            char *pLogFileStub = p2 + strlen(p2) +1 ; 
            char *p3; 
            char *p4;
            int r=0;

            if (lineLength <= strlen(p2)) {
                LogMessage(1, "ReadConfig: WARNING: line %d: you did not specify a logfile", lineNum);
                thisConfig->nWarnings++;
                continue; 
            }

            if (pLogFileStub==NULL) {
                LogMessage(1, "ReadConfig: WARNING: line %d: bad logfile format", lineNum);
                thisConfig->nWarnings++;
                continue; 
            }

            // work item 8433
            // handle logfile stubs that contain spaces.
            p3= pLogFileStub;  
            p4= pLogFileStub + strlen(pLogFileStub) - 1; 
            
            while((*p3 == ' ')||(*p3 == '\t')) p3++;       // skip leading spaces and TABs
            while((*p4 == ' ')||(*p4 == '\n')||(*p4 == '\r')||(*p4 == '\t')) *p4--='\0'; // trim trailing spaces

            if (*pLogFileStub=='\0') {
                LogMessage(1, "ReadConfig: WARNING: line %d: you did not specify a logfile", lineNum);
                thisConfig->nWarnings++;
                continue; 
            }

            sprintf_s( thisConfig->LogFileName, sizeof(thisConfig->LogFileName)/sizeof(thisConfig->LogFileName[0]), 
                       "%s.%d.log", p3, GetCurrentProcessId() );
            
            LogFileHasBeenSet= TRUE; 
            OpenLogfile();
            LogMessage(1, "ReadConfig: new log file name: '%s'", thisConfig->LogFileName);
            // check the directory against IniFileDirectory
            if (_strnicmp(IniFileDirectory,thisConfig->LogFileName, strlen(IniFileDirectory))==0) {
                LogMessage(1, "ReadConfig: WARNING: log file is under the ini file directory. Don't do this! Check the readme.");
                thisConfig->nWarnings++;
            }
        }

        else {
            LogMessage(1, "ReadConfig: WARNING: line %d: Ignoring line: '%s'", lineNum, p2);
            thisConfig->nWarnings++;
        }
    }

    if (currentCond!=NULL) {
        LogMessage(0, "ReadConfig: WARNING: Dangling %s found in ini file", DIRECTIVE_REWRITE_COND); 
        thisConfig->nWarnings++;
        FreeCondList(currentCond); 
    }

    thisConfig->nLines = lineNum;
    LogMessage(1, "ReadConfig: Done reading, found %d rules (%d errors, %d warnings) on %d lines", thisConfig->nRules, thisConfig->nErrors, thisConfig->nWarnings, thisConfig->nLines);


    // Mon, 25 Sep 2006  16:41
    // Tue, 27 Feb 2007  12:12
    // --------------------------------------------

    // There is timing condition where Windows reports changes, then IIRF
    // tries reading the file but fails, because the ini file is still open
    // for writing by someone else, and possibly because the write has not
    // completed.  In this case we get lineNum==1, and zero rules, etc.

    //
    // To handle this, we will delay a bit here, then re-try the reading
    // of the config file.  Without being able to reproduce the problem
    // reliably, it is hard to test out this solution.
    // 

    // Heuristically re-try, in the case where we have a one line ini file and zero rules.
    if ((lineNum == 1) && (thisConfig->nRules == 0) &&  (thisConfig->nErrors==0)) {
        // enforce a threshold on the number of retries 
        if (retryCount <= 16) {
            int period= 250;
            retryCount++;
            LogMessage(0, "ReadConfig: INFO: Just one line? IIRF is attempting to re-read the ini file...(Retry #%d)", 
                       retryCount); 
            fclose(infile);
            free(buffer);
            ReleaseConfig(thisConfig); // release whatever we allocated (probably nothing)
            // set the back-off schedule for the delay
            if ((retryCount % 2) == 0) period *= (retryCount / 2)*2;
            Sleep(period);
            return ReadConfig(ConfigFile, retryCount);
        }
        else {
            LogMessage(0, "ReadConfig; WARNING: IIRF Will now stop trying to re-read the ini file. (%d failed retries)", 
                       retryCount);
        }
    }


    // Tue, 27 Feb 2007  12:12
    // -------------------------------------------------------
    //
    // It's possible we retried repeatedly to read the file and kept failing
    // (getting one line, zero rules, etc).  In this case, we will keep the
    // new (essentially empty) configuration, but back off to the prior
    // logfile.  This will not actually address the timing issue, but should
    // at least provide some comforting insight into what is happening.
    // Without this mitigation, we get no logging whatsoever, because there is
    // no logfile specified in a 1 line ini file.  With no logging, it appears
    // that IIRF has just "gone dark." It's not so - it's just that IIRF has
    // no rules to apply, and no logfile into which to babble. So it *looks*
    // dark. If you could "touch" the ini file, IIRF should again wake back
    // up.
    // 
    // 
    // A side effect of this mitigation is that, for someone who has a valid
    // ini file of length 1 and does not intend to set the logfile within that
    // ini file, they will still get logging to the prior log file.  The
    // solution to that problem: make the ini file 2 lines long.
    //
    // 
    // NB:
    // There are some cases in which even a "touch" on the ini file, or even a
    // full-fledged edit and save, will not "wake up" IIRF. This could be
    // because the timing problem is recurring (in essence, we get a change
    // notification on ini file, but the file cannot be read). It is hard to
    // debug this. Attaching a debugger to the system seems to change the
    // behavior - it no longer "goes dark."
    // 

    if ((lineNum== 1) && !LogFileHasBeenSet && (thisConfig != NULL)) {
        // use the old filename for logging! 
        if ((config != NULL) && (config->LogFileName[0]!= '\0')) {
            strcpy_s( thisConfig->LogFileName, 
                      sizeof(thisConfig->LogFileName)/sizeof(thisConfig->LogFileName[0]), 
                      config->LogFileName);

            LogMessage(1, "ReadConfig: INFO: Re-using previous logfile because the changed ini file is suspisciously short.");
            LogMessage(1, "ReadConfig: INFO: You may have to \"touch\" or re-save the ini file to tell IIRF to re-read it.");
        }
    }


    fclose(infile);
    free(buffer);
    IniFileChanged= FALSE; 

    return thisConfig;
}



int ParseRuleModifierFlags(IirfConfig * cfg, char *directive, char * pModifiers, RewriteRule *rule)
{
    boolean inconsistent = FALSE;

    // workitem 23639
    //rule->IsRedirect= FALSE; 
    rule->IsForbidden= FALSE;
    rule->IsLastIfMatch= FALSE;
    rule->IsNotFound= FALSE;
    rule->IsGone= FALSE;
    rule->IsCaseInsensitive= FALSE;
    rule->RecordOriginalUrl= FALSE;
    rule->QueryStringAppend= FALSE;

    if (pModifiers==NULL) return 0;  // no flags at all

    LogMessage(4, "ParseRuleModifierFlags: '%s'", pModifiers);

    if ((pModifiers[0] != '[') || (pModifiers[strlen(pModifiers)-1] != ']')) {
        LogMessage(1, "WARNING: Badly formed RewriteRule modifier flags (ignored).");
        // With StrictParsing ON, the rule is ignored.  
        // With StrictParsing OFF, the badly formed modifiers are ignored, but the rule is kept.
        return (cfg->StrictParsing) ? 1 : 0;
    }
    else {
        char * p1, *p2;
        char * StrtokContext= NULL;
        p1= pModifiers+1; // skip leading '['
        pModifiers[strlen(pModifiers)-1]=0; // remove trailing ']'

        p2= strtok_s(p1, ",", &StrtokContext);  // split by commas
        while (p2 != NULL) {
            if (config->LogLevel >= 5 ) {
                LogMessage(5, "ParseRuleModifierFlags: token '%s'", p2);
            }

            if (p2[0]=='R') {  // redirect
                if (_strnicmp(directive,DIRECTIVE_REWRITE_RULE, strlen(DIRECTIVE_REWRITE_RULE))==0)
                {
                    // With StrictParsing ON, the RewriteRule with [R] flag is ignored.  
                    // With StrictParsing OFF, the RewriteRule with [R] flag is treated like a RedirectRule.
                    if (cfg->StrictParsing)
                        return -1;
                    // else fall through!
                }
                
                rule->IsRedirect= TRUE;
                rule->RedirectCode= REDIRECT_CODE_DEFAULT;   // use the default redirect code
                if ((p2[1]!=0) && (p2[1]=='=') && (p2[2]!=0)) {
                    int n= atoi(p2+2);
                    if ((n <= REDIRECT_CODE_MAX) && (n >= REDIRECT_CODE_MIN))
                        rule->RedirectCode= n;
                }
            }
            else if ((p2[0]=='F') && (p2[1]==0)) {  // forbidden (403)  [F]
                LogMessage(5, "rule: Forbidden");
                rule->IsForbidden= TRUE;
            }
            else if ((p2[0]=='G') && (p2[1]==0)) {  // Gone (410)  [G]
                LogMessage(5, "rule: Gone");
                rule->IsGone= TRUE;
            }
            else if ((p2[0]=='N') && (p2[1]=='F') && (p2[2]==0)) {  // not found (404)  [NF]
                LogMessage(5, "rule: Not found");
                rule->IsNotFound= TRUE;
            }
            else if ((p2[0]=='L')  && (p2[1]==0))  {  // Last rule to process if match [L]
                LogMessage(5, "rule: Last");
                rule->IsLastIfMatch= TRUE;
            }
            else if (((p2[0]=='I') && (p2[1]==0))   // case-insensitive  [I]
                     || ((p2[0]=='N') && (p2[1]=='C') && (p2[2]==0)) )  {  // Not Case-insensitive  [NC]
                LogMessage(5, "rule: Case Insensitive match");
                rule->IsCaseInsensitive= TRUE;
            }
            else if ((p2[0]=='U') && (p2[1]==0))  {  // Unmangle URLs  [U]
                LogMessage(5, "rule: Unmangle URLs");
                rule->RecordOriginalUrl= TRUE;
            }
            // workitem 19486
            else if ((p2[0]=='Q') && (p2[1]=='S') && (p2[2]=='A') && (p2[3]==0))  {  // Query-string Append  [QSA]
                LogMessage(5, "rule: Querystring Append");
                rule->QueryStringAppend= TRUE;
            }
            else {
                LogMessage(1, "WARNING: unsupported modifier flag '%s' on %s", p2, directive);

                if (cfg->StrictParsing)
                    return 1;
                // else ignore the unsupported modifier
            }

            p2= strtok_s(NULL, ",", &StrtokContext);  // next token
        }


        // consistency checks
        if (rule->IsForbidden && rule->IsRedirect) {
            LogMessage(1, "WARNING: Conflicting modifier flags - F,R");
            inconsistent = TRUE; 
        }
        if (rule->IsForbidden && rule->IsLastIfMatch) {
            LogMessage(1, "WARNING: Redundant modifier flags - F,L");
            inconsistent = TRUE; 
        }
        if (rule->IsForbidden && rule->IsNotFound) {
            LogMessage(1, "WARNING: Conflicting modifier flags - F,NF");
            inconsistent = TRUE; 
        }
        if (rule->IsForbidden && rule->IsGone) {
            LogMessage(1, "WARNING: Conflicting modifier flags - F,G");
            inconsistent = TRUE; 
        }

        if (rule->IsNotFound && rule->IsLastIfMatch) {
            LogMessage(1, "WARNING: Redundant modifier flags - NF,L");
            inconsistent = TRUE; 
        }
        if (rule->IsNotFound && rule->IsRedirect) {
            LogMessage(1, "WARNING: Conflicting modifier flags - NF,R");
            inconsistent = TRUE; 
        }
        if (rule->IsNotFound && rule->IsGone) {
            LogMessage(1, "WARNING: Conflicting modifier flags - NF,G");
            inconsistent = TRUE; 
        }

        if (rule->IsRedirect && rule->IsLastIfMatch) {
            LogMessage(1, "WARNING: Redundant modifier flags - R,L");
            inconsistent = TRUE; 
        }
        if (rule->IsRedirect && rule->IsGone) {
            LogMessage(1, "WARNING: Redundant modifier flags - R,G");
            inconsistent = TRUE; 
        }
        
        // workitem 19486
        if (rule->IsNotFound && rule->QueryStringAppend) {
            LogMessage(1, "WARNING: Conflicting modifier flags - NF,QSA");
            inconsistent = TRUE; 
        }
        if (rule->IsForbidden && rule->QueryStringAppend) {
            LogMessage(1, "WARNING: Conflicting modifier flags - F,QSA");
            inconsistent = TRUE; 
        }

        if (inconsistent && cfg->StrictParsing)
            return 1;

    }
    return 0;
}



void ParseCondModifierFlags(char * pModifiers, RewriteCondition *cond)
{
    cond->LogicalOperator= 0;
    cond->IsCaseInsensitive= FALSE;

    if (pModifiers==NULL) return;  // no flags at all

    LogMessage(3, "ParseCondModifierFlags: '%s'", pModifiers);

    if ((pModifiers[0] != '[') || 
        (pModifiers[strlen(pModifiers)-1] != ']')) {
        LogMessage(1, "WARNING: Badly formed RewriteCond modifier flags.");
        return;
    }
    else {
        char * p1, *p2;
        char * StrtokContext= NULL;
        p1= pModifiers+1;
        pModifiers[strlen(pModifiers)-1]=0; // remove trailing ']'

        p2= strtok_s(p1, ",", &StrtokContext);  // split by commas
        while (p2 != NULL) {
            if (config->LogLevel >= 5 ) {
                LogMessage(5, "ParseCondModifierFlags: token '%s'", p2);
            }
            if ((p2[0]=='O') && (p2[1]=='R') && (p2[2]==0)) {  // logical OR
                LogMessage(5, "Cond: Logical OR");
                cond->LogicalOperator= 1; // this will apply to the following RewriteCond in the ini file
            }
            else if (((p2[0]=='I') && (p2[1]==0))  // case-[I]nsensitive
                     || ((p2[0]=='N') && (p2[1]=='C') && (p2[2]==0)) ) {  // [N]ot [C]ase-insensitive
                LogMessage(5, "Cond: Case Insensitive match");
                cond->IsCaseInsensitive= TRUE;
            }
            else {
                LogMessage(1, "WARNING: unsupported RewriteCond modifier flag '%s'", p2);
            }

            p2= strtok_s(NULL, ",", &StrtokContext);  // next token
        }

    }
    return;
}



/* 
 * ReplaceServerVariables
 *
 * Purpose:
 * 
 *     Walks through InputString and replaces %{VARIABLE_NAME} with values of 
 *     the named server variable. The string is from RewriteCond Test strings, 
 *     or from RewriteRule Replacement patterns. 
 * 
 * Arguments:
 * 
 *     pfc - pointer to filter context
 * 
 *     InputString - a string embedding %{NAME} constructs. 
 * 
 * Returns:
 * 
 *     malloc'd string with values inserted.  caller must free!
 * 
 */
char * ReplaceServerVariables(PHTTP_FILTER_CONTEXT pfc, char *InputString)
{
    char *p1;
    char *outString= malloc(INTERNET_MAX_URL_LENGTH); 
    char *pOut= outString;
    boolean done= FALSE;
    char *StrtokContext= NULL;

    if (InputString == NULL) return "";
    if (InputString[0] == '\0') return "";
    else {
        // get a local copy of the string because strtok() actually changes it
        char *myCopy= malloc(strlen(InputString)+1); 
        strcpy_s(myCopy, strlen(InputString)+1, InputString);
        p1= myCopy;

        while (p1[0]!='\0') {
            if ((pfc!=NULL) && (p1[0]=='%') && ( p1[1]=='{' )) {
                /* we think we have a server variable */

                char *VariableName= strtok_s(p1+2, "}", &StrtokContext);  // find word surrounded by ending braces

                if (VariableName != NULL) {
                    char *Value= GetServerVariable(pfc, VariableName);
                    LogMessage(4, "ReplaceServerVariables: VariableName='%s' Value='%s'",
                               VariableName, Value);
                    
                    if(strcpy_s(pOut,INTERNET_MAX_URL_LENGTH-(int)(pOut-outString), Value)==0) {
                        pOut+= strlen(Value);
                        *pOut='\0';
                    }

                    p1+= strlen(VariableName)+2;  // advance the ptr past the closing brace
                    free(Value);
                }
                else {
                    LogMessage(2, "ReplaceServerVariables: VariableName not found? (no end brace?)");
                    // badly formed string, undefined behavior.
                }
            }
            else {
                // copy that character through
                *pOut= *p1;
                pOut++;
            }

            p1++;
        }
        *pOut='\0';

        LogMessage(4, "ReplaceServerVariables: InputString='%s' out='%s'",
                   InputString,outString);

        // work item 9024
        // http://www.codeplex.com/IIRF/WorkItem/View.aspx?WorkItemId=9024
        if ( myCopy != NULL ) 
            free( myCopy );
    }
    return outString;
}




void ApplyCaseConversionInPlace(char * s)
{
    // Do case conversion on the input string, 
    // We convert "in place."
    // This handles \L..\E  and \U..\E  as well as \l and \u
    // as with PERL replacement strings.

    // The problem is, this conversion may be applied to a pathname
    // and in Windows, pathnames might reasonably have sequences like \L and \u .
    // As a result we inadvertently do case conversion by using the backslash 
    // as the flag character.   So we need to use a different flag character.
    // I choose #.  
    
    char *pIn= s;  // begin again
    char *pOut= s; 
    int convert= 0;

    LogMessage(4, "ApplyCaseConversion: before '%s'", s);

    while (pIn[0]!='\0') {

        if (pIn[0]=='#') { // previously, backslash
            switch (pIn[1]) {
                case 'L':
                    pIn++;
                    convert=1; // lowercase
                    break;
                case 'U':
                    pIn++;
                    convert=2; // uppercase
                    break;
                case 'E':
                    pIn++;
                    convert=0; // end conversion
                    break;
                case 'l':
                    pIn++;
                    convert=3; // lowercase one character
                    break;
                case 'u':
                    pIn++;
                    convert=4; // uppercase one character
                    break;
                default:
                    // in case we have a slash and no meaningful character, pass it through.
                    *pOut= *pIn;
                    pOut++;  // step to the next char on output
                    break;
            }
        }
        else {
            switch (convert) {
                case 0: 
                    // do nothing
                    break;
                case 1: // lowercase
                    if ((*pIn >='A') && (*pIn <= 'Z')) *pIn+= ('a'-'A'); 
                    break;
                case 2: // uppercase
                    if ((*pIn >='a') && (*pIn <= 'z')) *pIn-= ('a'-'A'); 
                    break;
                case 3: // lowercase one char
                    if ((*pIn >='A') && (*pIn <= 'Z')) *pIn+= ('a'-'A'); 
                    convert=0;
                    break;
                case 4: // uppercase one char
                    if ((*pIn >='a') && (*pIn <= 'z')) *pIn-= ('a'-'A'); 
                    convert=0;
                    break;
            }
            *pOut= *pIn;
            pOut++;  // step to the next char on output
        }
        pIn++;  // step to the next char on input
    }
    *pOut = '\0'; // terminate

    LogMessage(3, "ApplyCaseConversion: after  '%s'", s);

}  // void ApplyCaseConversion(char * s)





char * GenerateReplacementString(char *ReplacePattern, 
                                 PcreMatchResult * RuleMatchResult, 
                                 PcreMatchResult * CondMatchResult)
/* 
 * Purpose:
 *
 *     generates a string using the given Replacement Pattern,
 *     the source string, and the vector of indexes into that
 *     string corresponding to substring matches.
 *
 * 
 * Arguments:
 * 
 *     ReplacePattern - the pattern to use to generate the
 *         output string. Any $N will be replaced with the
 *         corresponding match substring from the source.  Example: /bah/$1/$2
 *         Any %N will be replaced with the corresponding match
 *         substring from the most recently evaluated RewriteCond (Condition). 
 *         Example: 
 *              RewriteCond %{SERVER_NAME}          ([^\.]+)\.chiesa\.net$                [I]
 *              RewriteCond c:\Inetpub\wwwroot\%1   -d
 *              RewriteRule ^(.*)$                  /common/driver.aspx?url=$1&host=%1    [U,I,L]
 *
 *
 *     RuleMatchResult - the match result from the RewriteRule.  This contains: the
 *         source strings, typically a URL like /foo/bar/wee.php; the MatchCount,
 *         an integer indicating the number of matched substrings found in the
 *         result; and SubstringIndexes, a vector of integers.  The vector of
 *         contains the start and end indexes of the matched substrings, where
 *         Index[2n] is the start position and Index[2n+1] the end position of
 *         substring n, within the corresponding source string.  None of these
 *         fields get modified herein.
 *
 *     CondMatchResult - same as RuleMatchResult, but for the most recently evaluated 
 *         Condition. This may or may not be the RewriteCond positionally nearest
 *         the RewriteRule.  Because of logical precedence, RewriteCond's are not 
 *         necessarily evaluated in the order in which they appear in the ini file, 
 *         and not all RewriteCond's are evaluated at runtime. 
 * 
 * Returns:
 * 
 *     an allocated string.  The string must be freed by the caller.
 * 
 */
{
    char *p1= ReplacePattern; 
    char *outString= malloc(INTERNET_MAX_URL_LENGTH); 
    char *pOut= outString; 
    boolean done= FALSE;
    int i, j;

    char FlagChar[2];
    PcreMatchResult *MatchResult[2];

    // workitem 17391
    // check for "do nothing"
    if (ReplacePattern[0] =='-'  && ReplacePattern[1] =='\0' ) {
        strcpy_s(pOut, INTERNET_MAX_URL_LENGTH, RuleMatchResult->Subject);
        LogMessage(4, "GenerateReplacementString: do nothing... '%s'", outString);
        return outString;
    }

    FlagChar[0]='$';
    FlagChar[1]= config->CondSubstringBackrefFlag;  // default: '%'
    MatchResult[0]= RuleMatchResult;
    MatchResult[1]= CondMatchResult;

    // this stanza for logging only
    if ( config->LogLevel >= 4 ) {
        char MsgBuffer1[256];
        strcpy_s(MsgBuffer1,256,"[  ");
        for (i=0; i < 2; i++) {
            strcat_s(MsgBuffer1,256,"[  ");
            for(j=0; j<MatchResult[i]->MatchCount*2; j++) {
                char vecbuf[32];
                _itoa_s(MatchResult[i]->SubstringIndexes[j], vecbuf, 32, 10 );
                if (strlen(vecbuf) > 0) strcat_s(MsgBuffer1,256,vecbuf);
                else strcat_s(MsgBuffer1,256,"??");
                strcat_s(MsgBuffer1,256,", ");
            }
            MsgBuffer1[strlen(MsgBuffer1)-2]=']';
        }

        LogMessage(4, "GenerateReplacementString: src='%s','%s' ReplacePattern='%s' vec=[%s] counts=%d,%d", 
                   MatchResult[0]->Subject, 
                   MatchResult[1]->Subject, 
                   ReplacePattern, 
                   MsgBuffer1, 
                   MatchResult[0]->MatchCount, 
                   MatchResult[1]->MatchCount);
    }


    // here is where the work gets done
    while (p1[0]!='\0') {
        int ix= -1;
        if (p1[0]==FlagChar[0]) ix=0;
        else if (p1[0]==FlagChar[1]) ix=1;

        if ( (ix!=-1) && ( isdigit(p1[1]) )) {
            int n= atoi(p1+1);  // get the index of the back-ref. Eg, for '%2' it returns 2.
            if (n < MatchResult[ix]->MatchCount) {
                char *SubstringStart = MatchResult[ix]->Subject + MatchResult[ix]->SubstringIndexes[2*n];
                int SubstringLength = MatchResult[ix]->SubstringIndexes[2*n+1] - MatchResult[ix]->SubstringIndexes[2*n]; 
                strncpy_s(pOut, INTERNET_MAX_URL_LENGTH-(int)(pOut-outString), SubstringStart, SubstringLength);
                LogMessage(4, "GenerateReplacementString: replacing (%c%d) with '%s'", FlagChar[ix], n, pOut);
                pOut+= SubstringLength;
            }
            else {
                
                int skip= (n==0) ? 1 : (int) log10((double)n) + 1;

                // Sat, 16 Feb 2008  21:06
                //
                // This branch may execute when URL-escaped characters, such as %3d
                // and %3F, are in the replacement pattern, for example when
                // HTTP_REFERER is used in the replacement pattern.
                //
                // In all cases, this logic interprets %nn as a back-reference, when
                // in reality it may be a URL escaped char.  Problem.  No one is
                // complaining about this so I will not fix it yet.
                //
                // The approach now is to just pass through the % backref unchanged.
                // This may or may not be correct or desired behavior. 
                // Let's take the case where there is a %3F, and no 3 reference.  In this 
                // case the %3F is passed through, which seems correct.
                //
                // Let's take the case where there is a %2A, and there is a 2 reference.  In this 
                // case the %2 is replaced, and the A remains.  This is probably not what was 
                // intended. 
                //
                // In order to handle that case, we need a different backref flag character.
                // That's what the DIRECTIVE_COND_SUBSTRING_FLAG directive is for.   
                // Using that directive, you can change the back-ref flag char 
                // to something other than %.  

#ifdef PEDANTIC 
                LogMessage(2, "GenerateReplacementString: Attention: Either we have a Substring index out of range, or the URL is using escaped chars (%c%d)", FlagChar[ix], n);

                // Copy the FlagChar to the output. 
                *pOut= *p1;  
                // Skip one char on input;  later after we fall through this loop, we'll skip the rest.
                p1++; 
                // Advance the pointer on the output buffer, one character.
                pOut++;

                // determine the number of digits to pass through
                for (i=0; i < skip; i++)
                {
                    pOut[i]= p1[i];
                }
                pOut+= skip;
                
                // workitem 17299
                // Tue, 08 Jul 2008  08:40
                // penghao - correct ptr arithmetic.
                // *pOut++= p1[i];
                p1--;
                #else
                // the back ref evaluates to "nothing"
#endif
                
            }

            // step over the number we found
            if (n>0) {
                // determine the number of digits to skip
                int skip=(int) log10((double)n) + 1;
                p1+= skip;
            }
            else
                p1++; 

        }
        else 
            // The character following the FlagChar is not a digit.

            // workitem 9910: http://www.codeplex.com/IIRF/WorkItem/View.aspx?WorkItemId=9910
            // allow % or $ in the output of the replacement string. 
            // first added in release v1.2.12a

            // If the char is the same as the flag char, treat it like an escape for the flag char. 
            // The net effect is to reduce a double-FlagChar to a single-FlagChar.
            if ((ix!=-1) && (p1[0]==p1[1])) { 

                // Copy the first FlagChar to the output. 
                *pOut= *p1;  
                // Skip one char on input;  we'll skip the second flagChar in the input,
                // later after we fall through this loop.
                p1++; 
                // Advance the pointer on the output buffer, one character.
                pOut++;
            }
            else {
                // pass through
                *pOut= *p1;
                pOut++;
            }

        // step over the char, either ($ or %) or a non-flag char
        p1++;
        
        //========================= new code starts here ==================================
        // check for string full
        if (INTERNET_MAX_URL_LENGTH <= (int)(pOut-outString)+2) {
            // terminate
            outString[INTERNET_MAX_URL_LENGTH-1]='\0';
            LogMessage(4,"URL too long after substitution:%s",outString);
            break; 
        }
        //========================= new code ends here ==================================
    }
    *pOut='\0';

    ApplyCaseConversionInPlace(outString); 

    LogMessage(4, "GenerateReplacementString: result '%s'", outString);

    return outString;
}



void FreeCondList(RewriteCondition * cond) 
{
    if (cond == NULL) return ;

    if (cond->RE!= NULL) free(cond->RE);
    if (cond->TestString != NULL)  free(cond->TestString);
    if (cond->Pattern != NULL)  free(cond->Pattern);
    
    if (cond->Child != NULL)  FreeCondList(cond->Child);  // recurse

    free(cond);
    return;
}



void FreeRuleList (RewriteRule * ruleNode) 
{
    if (ruleNode==NULL) return ;
    if (ruleNode->RE != NULL) free(ruleNode->RE);
    if (ruleNode->HeaderToRewrite != NULL) free(ruleNode->HeaderToRewrite);
    if (ruleNode->Pattern != NULL) free(ruleNode->Pattern);
    if (ruleNode->Replacement != NULL) free(ruleNode->Replacement);

    FreeCondList(ruleNode->Condition);

    if (ruleNode->next != NULL) FreeRuleList(ruleNode->next);

    free (ruleNode);
    return; 
}



void ReleaseConfig (IirfConfig * deadConfig) 
{
    if (deadConfig==NULL) return;
    FreeRuleList(deadConfig->rootRule);
    if (deadConfig->StatusUrl)
        free(deadConfig->StatusUrl); 
    free(deadConfig); 
    return; 
}



boolean EvalCondition(
    HTTP_FILTER_CONTEXT * pfc, 
    PcreMatchResult * RuleMatchResult, 
    PcreMatchResult * CondMatchResult, 
    RewriteCondition * cond)
{
    // check to see if this condition applies
    char *FormatString1= "EvalCondition: checking '%s' against pattern '%s'";
    char * ts1;
    char * ts2;
    boolean retVal= FALSE;

    if (cond == NULL) return TRUE; // no condition exists, implies TRUE

    ts1= ReplaceServerVariables(pfc, cond->TestString);

    LogMessage(3, "EvalCondition: ts1 '%s'", ts1);

    // Replace Back-references.  
    // Back-refs  are  $n or %n  references in the TestString, they get replaced by
    // the matched substrings from the respective subject strings. 
    // Also, do case conversion where directed. 
    ts2= GenerateReplacementString(ts1, RuleMatchResult, CondMatchResult);

    free(ts1);

    LogMessage(3, FormatString1, ts2, cond->Pattern);

    if ((cond->SpecialConditionType == 'd') || 
        (cond->SpecialConditionType == 'f') ||
        (cond->SpecialConditionType == 's') ) {

        // Strategy:  evaluate the condition, then apply the negation (if any) to the result.

        // check for the directory or file
        WIN32_FIND_DATA fileData;
        int last= strlen(ts2);
        HANDLE hFind;

        LogMessage(4, "EvalCondition: cond->SpecialConditionType= '%c'", 
                   cond->SpecialConditionType);

        if (ts2[last-1]=='\\') 
            ts2[last-1]='\0';

        hFind = FindFirstFile(ts2, &fileData);
        free(ts2);

        if (hFind == INVALID_HANDLE_VALUE) {
            // the given string is not a file and it is not a directory
            retVal= FALSE; // the file does not exist // the directory does not exist // it is not a file with non-zero size
            LogMessage(5, "EvalCondition: Special: it is not a file; not a directory");
        }
        else {
            // the handle is valid; it is either a file or a directory. 

            switch (cond->SpecialConditionType) {
                case 'd':
                    // retVal indicates it is a directory
                    retVal= (boolean) (fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
                    LogMessage(5, "EvalCondition: Special: is it a directory? (%s)", retVal?"yes":"no");
                    break;

                case 'f':
                    // retVal indicates it is a file
                    retVal= (boolean) !(fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
                    LogMessage(5, "EvalCondition: Special: is it a file? (%s)", retVal?"yes":"no");
                    break;

                case 's': // meaning:  regular file with non zero size
                    // verify it is NOT a directory (ergo, a file), and verify that it has non-zero size
                    LogMessage(5, "EvalCondition: Special: is it a non-zero sized file?");
                    retVal=  (!(fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                              ((fileData.nFileSizeHigh  != 0) || (fileData.nFileSizeLow != 0)));
                    break;
            }

            // close the handle
            FindClose(hFind);
        }

        if (cond->IsSpecialNegated) retVal = !retVal; 

        LogMessage(4, "EvalCondition: Special, retVal= %s", retVal?"True":"false");
    }
    else {
        // now test if ts2 matches the pattern for the RewriteCond

        // free any previously allocated Cond subject string
        if (CondMatchResult->Subject) free(CondMatchResult->Subject);  

        CondMatchResult->Subject= ts2;  // we will free this later
        CondMatchResult->MatchCount = 
            pcre_exec(cond->RE,                          /* the compiled pattern */
                      NULL,                              /* no extra data - we didn't study the pattern */
                      ts2,                               /* the subject string */
                      strlen(ts2),                       /* the length of the subject */
                      0,                                 /* start at offset 0 in the subject */
                      0,                                 /* default options */
                      CondMatchResult->SubstringIndexes, /* pre-allocated output vector for substring position info */
                      config->MaxMatchCount*3);          /* number of elements allocated in the output vector */

        /* The CondMatchResult will be used in any successive iterations for "back references" of the form %n */

        if ( CondMatchResult->MatchCount < 0) {
            if (CondMatchResult->MatchCount == PCRE_ERROR_NOMATCH) {
                LogMessage(3, "EvalCondition: match result: %d (No match)", CondMatchResult->MatchCount );
            }
            else {
                LogMessage(1, "EvalCondition: WARNING: match result: %d (unknown error)", CondMatchResult->MatchCount);
            }
        }
        else {
            LogMessage(3,"EvalCondition: match result: %d (match)", CondMatchResult->MatchCount );
            retVal= TRUE;  // this condition evaluates to true
        }
    } 


    // Follow the chain of additional conditions...
    if (cond->Child != NULL) {

        boolean MustEvaluateChild= 
            (retVal && (cond->LogicalOperator==0)) ||  // first branch TRUE, AND operator 
            (!retVal && (cond->LogicalOperator==1))  ;  // first branch FALSE, OR operator

        LogMessage(5,"EvalCondition: Child is non NULL (parent= 0x%08X) (child= 0x%08X)", cond, cond->Child);

        // this stanza for logging only.
        // DANGER! we log separately from actually evaluating the MustEvaluateChild. 
        // So there is in effect, redundant, parallel logic here, which may get de-synchronized.
        // Be careful modifying the above or the below.  

        if ( config->LogLevel >= 5 ) {
            if (retVal) {
                // The current condition evaluates to TRUE.
                LogMessage(5, "EvalCondition: Current condition evaluates to TRUE");

                // If the next Condition is linked by a logical 'OR', then no need to evaluate. 
                // Since the first branch is TRUE, the OR of that branch with anything will be TRUE.  

                // if the next Condition is linked by a logical 'AND', evaluate it.
                if (cond->LogicalOperator==0)  // AND
                    LogMessage(5, "EvalCondition: Logical AND, ergo we evaluate the Child");
                else
                    LogMessage(5, "EvalCondition: Logical OR, ergo no need to evaluate Child condition");
            }
            else {
                // The current condition evaluates to FALSE.
                LogMessage(5, "EvalCondition: Current condition evaluates to FALSE");

                // If the next Condition is linked by a logical 'AND', then no need to evaluate. 
                // Since the first branch is FALSE, the AND of that branch with anything will be FALSE.

                // OTOH, if the LogicalOperator is 'OR', then we must evaluate it.  
                if (cond->LogicalOperator==1) // OR
                    LogMessage(5, "EvalCondition: Logical OR, ergo we evaluate the Child");
                else 
                    LogMessage(5, "EvalCondition: Logical AND, ergo no need to evaluate Child condition");

            }
        }

        if (MustEvaluateChild)
            retVal = EvalCondition(pfc, 
                                   RuleMatchResult, 
                                   CondMatchResult, 
                                   cond->Child);
    }
    else
        LogMessage(5, "EvaluateCondition: Child is NULL");


    LogMessage(3, "EvalCondition: returning %s", retVal ? "TRUE" : "FALSE");
    return retVal; 
}



void FreeMatchResult(PcreMatchResult *mr)
{
    if (mr==NULL) return;
    if (mr->Subject!=NULL) free(mr->Subject);
    if (mr->SubstringIndexes!=NULL) free(mr->SubstringIndexes);
    return;
}




/* 
 * Purpose:
 *
 *     evaluate a condition list, return true or false. 
 * 
 * Arguments:
 * 
 *     pfc - filter context.  This is used to get to Server variables.
 *         The Condition may include referece to Server variables.
 *
 *     RuleMatchResult - the match result from the RewriteRule.  This contains: the
 *         source strings, typically a URL like /foo/bar/wee.php; the MatchCount,
 *         an integer indicating the number of matched substrings found in the
 *         result; and SubstringIndexes, a vector of integers.  The vector of
 *         contains the start and end indexes of the matched substrings, where
 *         Index[2n] is the start position and Index[2n+1] the end position of
 *         substring n, within the corresponding source string.  None of these
 *         fields get modified inside this procedure. 
 *
 *     CondMatchResult - same as RuleMatchResult, but this match result applies to the most recently evaluated 
 *         Condition. (This may or may not be the RewriteCond positionally nearest the
 *         RewriteRule.  Due to logical precedence, RewriteCond's are not necessarily
 *         evaluated in the order in which they appear in the ini file, and it may be
 *         that not all RewriteCond's listed in the file are evaluated at runtime.)
 *         This structure is filled in by this procedure, if the return value is true.
 *         If the return value is false, then the CondMatchResult is not meaningful.
 * 
 * 
 * Side Effects:
 * 
 *     If the condition chain evaluates to true, then this procedure allocates memory
 *     for storing the Condition result (CondMatchResult). The caller must free this
 *     memory later, via FreeMatchResult().  If the condition chain evaluates to false,
 *     the caller does not need to free CondMatchResult.
 * 
 * 
 * Returns:
 * 
 *     true or false.
 * 
 */
boolean EvalConditionList(
    HTTP_FILTER_CONTEXT * pfc, 
    int ruleNum,
    PcreMatchResult *RuleMatchResult, 
    /* out */ PcreMatchResult *CondMatchResult, 
    RewriteCondition * RootCondition)
{
    boolean result= FALSE;
    if (RootCondition == NULL) {
        // no condition exists, implies the rule will always apply.
        LogMessage(3, "EvalConditionList: rule %d,  RootCondition is NULL => TRUE, Rule will apply", ruleNum);
        return TRUE;
    }

    // ok, we are going to evaluate one or more conditions, so we need to initialize and
    // allocate space for out results.  The PCRE doc says vector length should be 3n??
    // why? seems like it ought to be 2n.  or maybe 2n+1. In any case we alloc 3n.
    CondMatchResult->SubstringIndexes= (int *) malloc((config->MaxMatchCount*3)*sizeof(int));  
    CondMatchResult->Subject= NULL;
    CondMatchResult->MatchCount= 0;

    // EvalCondition walks the Condition tree
    result= EvalCondition(pfc, 
                          RuleMatchResult, 
                          CondMatchResult, 
                          RootCondition);

    LogMessage(3, "EvalConditionList: rule %d, %s", ruleNum, result ? "TRUE, Rule will apply" : "FALSE, Rule does not apply");

    // WorkItem URL:  http://www.codeplex.com/IIRF/WorkItem/View.aspx?WorkItemId=9858
    // free CondMatchResult->SubstringIndexes here in the case that the result is false (rule does not apply)
    if (!result) FreeMatchResult(CondMatchResult);

    return result;
}




/* AppendQueryString
 * 
 * Purpose:
 * 
 *     Append the original query string to the given string. In support 
 *     of the QSA flag.
 * 
 * Arguments:
 * 
 *     string - the string to append to. 
 *
 * Returns:
 * 
 *     char * containing query string with original query string appended.
 *     The caller must free this char *.
 * 
 */
char * AppendQueryString(
    HTTP_FILTER_CONTEXT * pfc,
    char *rewrittenUrl)
{
    // workitem 19486
    char *originalQuerystring= GetServerVariable(pfc, "QUERY_STRING");

    if (originalQuerystring[0] == '\0')
    {
        // nothing to do
        free(originalQuerystring);
        return rewrittenUrl;
    }
    else
    {
        
    // at this point we know there is an original query string, and
    // a rewritten URL.
    
    // is there a question mark in the rewritten URL?
    char * s=  (char *) strchr(rewrittenUrl, '?');
    
    // add ? if necessary, else use & separator
    char marker= (s != NULL) ? '&' : '?' ;

    // if the original URL ends in a ?, then the appended URL will end in a &

    int len= _scprintf("%s%c%s", rewrittenUrl, marker, originalQuerystring) + 1;
    char *newString = malloc(sizeof(char) * len);
    int ignore= sprintf_s(newString, len, "%s%c%s", rewrittenUrl, marker, originalQuerystring);

    free(originalQuerystring);
    return newString;
    }
}




/* StatusRequestAuthorized
 * 
 * Purpose:
 * 
 *     Checks for authorization of the status inquiry. 
 * 
 * Arguments:
 * 
 *     pfc - pointer to filter context
 *
 * Returns:
 * 
 *     TRUE = status request is authorized
 * 
 */
boolean StatusRequestAuthorized(
    HTTP_FILTER_CONTEXT * pfc)
{
    char * remoteAddr;
    char * localAddr;
    boolean result;
    if (config->AllowRemoteStatus) return TRUE;
    
    remoteAddr= GetServerVariable(pfc, "REMOTE_ADDR");
    localAddr= GetServerVariable(pfc, "LOCAL_ADDR");
    if (strncmp(remoteAddr, localAddr, strlen(localAddr)) == 0)
        result= TRUE;

    free (localAddr);
    free (remoteAddr);

    return result;
}




/* must export this to allow the test driver to work */
/* EXPORT */
int EvaluateRules( 
    HTTP_FILTER_CONTEXT * pfc, 
    HTTP_FILTER_AUTH_COMPLETE_INFO * pHeaderInfo,
    char * OrigUri, 
    int depth, 
    /* out */ char **result, 
    /* out */ boolean *pRecordOriginalUrl
    ) 
{
    RewriteRule * current= config->rootRule;
    int retVal= 0;  // 0 = do nothing, 1 = rewrite, 403 = forbidden, other = redirect
    int c=0;
    int RuleMatchCount; 
    int *RuleMatchVector;
    char *subject;
#if ARTIFICIAL_FAIL    
    char * artificialFailUrl = "/artificialFail";
#endif    

    LogMessage(3, "EvaluateRules: depth=%d", depth);

    // workitem 23459
    if (config->StatusUrl &&  (_strnicmp(OrigUri, config->StatusUrl, strlen(config->StatusUrl))==0)) {
        // caller is requesting IIRF status
        if (StatusRequestAuthorized(pfc)) {
            return 200;
        }
    }
        
    // workitem 23458
    if (config->EngineOff) 
    {
        LogMessage(6, "EvaluateRules: site EngineOff, no action");
        return 0;
    }


#if ARTIFICIAL_FAIL    
    // artificial fail
    if (strlen(OrigUri) >= strlen(artificialFailUrl) 
        && _strnicmp(OrigUri+strlen(OrigUri)-strlen(artificialFailUrl), artificialFailUrl, strlen(artificialFailUrl))==0) {
        // caller is requesting a failure injection
        char * failPtr = (char *) 0;
        // This will fail with an Access Violation
        LogMessage(1, "EvaluateRules: request for artificial failure");
        (*failPtr) = 8;
        // not reached
        return 1200;
    }
#endif
    
    if (current==NULL) {
        LogMessage(2, "EvaluateRules: No rewrite rules available.");
        return 0;
    }
    
    
    // The PCRE doc says vector length should be 3n??  why? seems like it ought to be 2n.  or maybe 2n+1.
    // In any case we allocate 3n according to the doc. 
    RuleMatchVector= (int *) malloc((config->MaxMatchCount*3)*sizeof(int));  

    // The way it works:  First we evaluate the URL request, against the RewriteRule pattern. 
    // If there is a match, then the logic evaluates the Conditions attached to the rule. 
    // This may seem counter-intuitive, since the Conditions appear BEFORE the rule in the file.
    // The Rule is evaluated FIRST.  

    // TODO: employ a MRU cache to map URLs
    while (current!=NULL) {
        c++;

        if (current->HeaderToRewrite != NULL)
        {
            subject = GetHeader_AutoFree(pfc, pHeaderInfo, current->HeaderToRewrite);
            if (subject == NULL)
            {
                LogMessage(3, "EvaluateRules: Header %s evaluates to nothing", current->HeaderToRewrite);
                subject= "";
            }
        }
        else
            subject = OrigUri;

        RuleMatchCount = pcre_exec(  
            current->RE,          /* the compiled pattern */
            NULL,                 /* no extra data - we didn't study the pattern */
            subject,              /* the subject string */
            strlen(subject),      /* the length of the subject */
            0,                    /* start at offset 0 in the subject */
            0,                    /* default options */
            RuleMatchVector,              /* output vector for substring position information */
            config->MaxMatchCount*3);     /* number of elements in the output vector */

        // return code: >=0 means number of matches, <0 means error
        
        if (RuleMatchCount < 0) {
            if (RuleMatchCount== PCRE_ERROR_NOMATCH) {
                LogMessage(3, "EvaluateRules: Rule %d : %d (No match)", c, RuleMatchCount );
            }
            else {
                LogMessage(2, "EvaluateRules: Rule %d : %d (unknown error)", c, RuleMatchCount);
            }
        }
        else if (RuleMatchCount == 0) {
            LogMessage(2, "EvaluateRules: Rule %d : %d (The output vector (%d slots) was not large enough)", 
                       c, RuleMatchCount, config->MaxMatchCount*3);
        }
        else {
            // we have a match and we have substrings
            boolean ConditionResult= FALSE;

            PcreMatchResult RuleMatchResult;
            PcreMatchResult CondMatchResult; 

            LogMessage(3, "EvaluateRules: Rule %d : %d matches", c, RuleMatchCount);

            // easier to pass these as a structure
            RuleMatchResult.Subject= subject;
            RuleMatchResult.SubstringIndexes= RuleMatchVector;
            RuleMatchResult.MatchCount= RuleMatchCount;

            // The fields in CondMatchResult may be filled by the EvalConditionList(), but
            // we must init them because the EvalConditionList may never be called.  The
            // results reflect only the "last" Condition evaluated.  This may or may not be
            // the final Condition in the file; the evaluation engine won't evaluate
            // Conditions unnecessarily.  Check the readme for more details.
            CondMatchResult.Subject= NULL;
            CondMatchResult.SubstringIndexes= NULL;
            CondMatchResult.MatchCount= 0;

            // evaluate the condition list, if there is one.  
            ConditionResult= 
                (current->Condition==NULL) || 
                EvalConditionList(pfc, 
                                  c,
                                  &RuleMatchResult, 
                                  &CondMatchResult, 
                                  current->Condition);


            // Check that any associated Condition evaluates to true, before 
            // applying this rule. 
            if ( ConditionResult ) {

                // workitem 19136
                if (current->IsForbidden) {
                    // no recurse 
                    *result= NULL; 
                    retVal = 403; //  = forbidden
                }
                else if (current->IsNotFound) {
                    // no recurse 
                    *result= NULL; 
                    retVal = 404; //  = not found
                }
                else if (current->IsGone) {
                    // no recurse 
                    *result= NULL; 
                    retVal = 410; //  = Gone
                }
                else {
                    
                    // create the replacement string
                    //int r=0;
                    char *ts1;
                    char *newString;

                    // generate the replacement string
                    // step 1: substitute server variables, if any.
                    ts1= ReplaceServerVariables(pfc, current->Replacement);

                    // step 2: substitute back-references as appropriate.
                    newString= GenerateReplacementString(ts1, // current->Replacement,
                                                         &RuleMatchResult, 
                                                         &CondMatchResult);
                    free(ts1);
                    FreeMatchResult(&CondMatchResult);

                    // pfc->AddResponseHeader(); // to add a header to the response?.

                    // set output params
                    if (current->HeaderToRewrite != NULL) {
                        if (pfc!=NULL && pHeaderInfo!=NULL) {
                            boolean retVal;
                            LogMessage(2,"EvaluateRules: Result (length %d): %s", strlen(newString), newString);
                    
                            LogMessage(4, "EvaluateRules: Setting request Header: '%s' = '%s'", current->HeaderToRewrite, newString); 
                            retVal= pHeaderInfo->SetHeader(pfc, current->HeaderToRewrite, newString); 
                            if (!retVal)
                                LogMessage(4, "EvaluateRules: Failed Setting Header: %d", GetLastError());
                        }
                        else {
                            LogMessage(4, "EvaluateRules: Want-to-but-cannot Set-Header: '%s' = '%s'", 
                                       current->HeaderToRewrite, newString); 
                        }
                        free(newString);
                        newString = NULL;
                    }
                    else
                    {
                        // we are rewriting the URL
                        // workitem 19486
                        if (newString!= NULL && current->QueryStringAppend) {
                            char * orig = newString;
                            //LogMessage(4, "EvaluateRules: QSA: %s", newString);
                            newString = AppendQueryString(pfc, newString);
                            if (newString != orig) free(orig);
                        }
                        LogMessage(2,"EvaluateRules: Result (length %d): %s", strlen(newString), newString);

                        *result= newString; 
                    }


                // if the current rule asks to record the original URL, then set the OUT flag. 
                *pRecordOriginalUrl |= current->RecordOriginalUrl;

                
                // check modifiers
                if (current->IsRedirect) {
                    retVal = current->RedirectCode;  // = redirect
                }
                else {
                    // rewrite (only if not setting a header
                    retVal=(current->HeaderToRewrite != NULL) ? 0 : 1;  // 0 = no rewrite, 1 = rewrite
                    if (current->IsLastIfMatch) {
                        // no recurse 
                        LogMessage(2,"EvaluateRules: Last Rule");
                        break;
                    }
                    else {
                        // by default, we recurse on the RewriteRules.
                        if (depth < config->IterationLimit) {
                            char * t;
                            int rv;
                            subject = (current->HeaderToRewrite != NULL) ? OrigUri : newString; 
                            rv= EvaluateRules(pfc, pHeaderInfo, subject, depth+1, &t, pRecordOriginalUrl);
                            if (rv) { 
                                *result= t;  // a newly allocated string
                                retVal= rv;  // for return to caller

                                // if we've rewritten in a later rule, free our string, we no longer need it.
                                if (newString != NULL)
                                    free(newString); 
                            }
                            // else, no match on recursion, so don't free newString (keep the existing result).
                        }// free our string, we no longer need it
                        else {
                            LogMessage(2, "EvaluateRules: Iteration stopped; reached limit of %d cycles.", 
                                       config->IterationLimit);
                        }
                    }
                }

                }

                break;  // break out of while loop on the first match
            }
        }

        // We did not break out of the loop. 
        // Therefore, this rule did not apply. 
        // Therefore, go to the next rule. 
        if (current!=NULL)
            current= current->next;
    }

    free(RuleMatchVector);

    LogMessage(3,"EvaluateRules: returning %d", retVal);
    return retVal;
}




#define DEFAULT_BUFFER_SIZE         1024
#define MAX_BUFFER_SIZE             4096
/* GetServerVariable
 * 
 * Purpose:
 * 
 *     gets teh value of the named server variable.
 * 
 * Arguments:
 * 
 *     VariableName - the name of the server variable, eg, QUERY_STRING, URL, etc
 *
 * Returns:
 * 
 *     char * containing the value of the variable.
 *     If the named server variable is unknown, then this method returns an empty string.
 *     The caller must free this char *, even if it is empty.
 * 
 */

char * 
GetServerVariable(
    HTTP_FILTER_CONTEXT * pfc,
    char * VariableName
    )
{
    BOOL   fRet = FALSE;
    CHAR * pszBuf = (CHAR *) malloc(DEFAULT_BUFFER_SIZE);
    DWORD  cbBuf = DEFAULT_BUFFER_SIZE;

    LogMessage(5,"GetServerVariable: getting '%s'", VariableName);

    if ( pszBuf == NULL ) {
        SetLastError( ERROR_NOT_ENOUGH_MEMORY );
        goto GSV2_Finished;
    }

    // workitem 15113
    pszBuf[0]='\0';

    // short circuit in test scenario
    if (pfc==NULL)
    {
        strcpy_s(pszBuf,DEFAULT_BUFFER_SIZE,"NoServer-");
        strcat_s(pszBuf,DEFAULT_BUFFER_SIZE, VariableName);
        return pszBuf;
    }
    
    // handle special variable name(s) (currently there is only one).
    if (strcmp(VariableName, "REQUEST_FILENAME")==0) {
        IirfRequestContext *ctx = (IirfRequestContext *) pfc->pFilterContext;
        LogMessage(5,"GetServerVariable: special variable name");
        // sometimes ctx is NULL
        if((ctx != NULL) && (ctx->Magic == IIRF_CONTEXT_MAGIC_NUMBER) && (ctx->PhysicalPath!=NULL)) {
            strcpy_s(pszBuf,DEFAULT_BUFFER_SIZE,ctx->PhysicalPath);
            cbBuf= strlen(ctx->PhysicalPath);
        }
        else {
            strcpy_s(pszBuf,DEFAULT_BUFFER_SIZE,VariableName);
            cbBuf= strlen(pszBuf);
        }
    }
    else {
        fRet = pfc->GetServerVariable( pfc, VariableName, pszBuf, &cbBuf );

        if ( fRet == FALSE ) {
            if ( GetLastError() == ERROR_INSUFFICIENT_BUFFER && cbBuf < MAX_BUFFER_SIZE ) {
                
                LogMessage(5,"GetServerVariable: Buffer not large enough.");

                //
                // Buffer is not large enough.
                // Reallocate but bound it to MAX_BUFFER_SIZE.
                // We could try to use cbBuf as the buffer size, but I have a hard limit at MAX_B_SIZE
                // just to be safe. 
                //
                free(pszBuf);
                pszBuf = (CHAR *) malloc(MAX_BUFFER_SIZE);
                if ( pszBuf == NULL ) {
                    SetLastError( ERROR_NOT_ENOUGH_MEMORY );
                    goto GSV2_Finished;
                }

                // workitem 15113
                pszBuf[0]='\0';

                cbBuf = MAX_BUFFER_SIZE;
                fRet = pfc->GetServerVariable( pfc,
                                               VariableName,
                                               pszBuf,
                                               &cbBuf );
                if ( fRet == FALSE )
                {
                    LogMessage(1,"GetServerVariable failed. This is a surprise!");
                    //
                    // Unexpected failure. Bail.
                    //
                    strcpy_s(pszBuf,MAX_BUFFER_SIZE,VariableName);
                }
            }
            else if ( GetLastError() == ERROR_INVALID_INDEX )
            {
                //
                // Did not find the named Server Variable.
                //
                LogMessage(2,"GetServerVariable: cannot find that variable");
                // cbBuf= 0;  // not needed
                strcpy_s(pszBuf,DEFAULT_BUFFER_SIZE,VariableName);
            }
            else {
                LogMessage(3,"GetServerVariable: ???");
                strcpy_s(pszBuf,DEFAULT_BUFFER_SIZE,VariableName);
            }

        }
    }

GSV2_Finished:

    // this stanza for logging only
    if ( config->LogLevel >= 5 ) {
        int r=0;
        LogMessage(5,"GetServerVariable: %d bytes", cbBuf);
        LogMessage(5,"GetServerVariable: result '%s'", pszBuf);
    }

    //
    // At this point, pszBuf points to the variable value and
    // cbBuf indicates size of buffer, including terminating NULL.
    //

    return pszBuf;
}


char * 
GetServerVariable_AutoFree(
                           HTTP_FILTER_CONTEXT * pfc,
                           char * VariableName
    )
{
  BOOL                            fRet = FALSE;
  DWORD                           dwSize = 128; // default size
  CHAR *                          pszBuf ;

  LogMessage(5,"GetServerVariable_AutoFree: getting '%s'", VariableName);
  if (pfc==NULL)
  {
      // happens in a testing context
      LogMessage(5,"GetServerVariable_AutoFree: no PFC, returning '%s'", VariableName);
      return VariableName;
  }
  pszBuf = (char *) pfc->AllocMem(pfc, dwSize, 0);

  if ( pszBuf == NULL ) {
    SetLastError( ERROR_NOT_ENOUGH_MEMORY );
    goto GSV_Finished;
  }

  // workitem 15113
  pszBuf[0]='\0';

  fRet = pfc->GetServerVariable( pfc, VariableName, pszBuf, &dwSize );
  if (fRet==FALSE) {
    if ((GetLastError() != ERROR_INSUFFICIENT_BUFFER) || (dwSize > INTERNET_MAX_URL_LENGTH ))
      goto GSV_Finished;

    // AllocMem allocates memory that is scoped to the HTTP request; 
    // The memory is automatically free'd in completion of the request. 
    pszBuf= (char *) pfc->AllocMem(pfc, dwSize, 0);
    if ( pszBuf == NULL ) {
      SetLastError( ERROR_NOT_ENOUGH_MEMORY );
      goto GSV_Finished;
    }
    // workitem 15113
    pszBuf[0]='\0';
    fRet = pfc->GetServerVariable( pfc, VariableName, pszBuf, &dwSize );
    if ( fRet == FALSE )
      goto GSV_Finished;
  }


GSV_Finished:
  if ( fRet == FALSE ) {
    int lastError= GetLastError();
    LogMessage(5,"GetServerVariable_AutoFree - %s (GetLastError()=%d)", 
               (lastError == ERROR_INVALID_INDEX) ? "no joy":"failed", 
               GetLastError());
  }

  LogMessage(5,"GetServerVariable_AutoFree: %d bytes", dwSize);
  LogMessage(5,"GetServerVariable_AutoFree: result '%s'", pszBuf);
    
  //
  // At this point, pszBuf points to the variable value (if any) and
  // dwSize indicates size of buffer, including terminating NULL.
  //

  return pszBuf;
}




char * 
GetHeader_AutoFree(
                  HTTP_FILTER_CONTEXT * pfc,
                  HTTP_FILTER_AUTH_COMPLETE_INFO * pHeaderInfo,
                  char * variableName
    )
{
    BOOL   fRet = FALSE;
    DWORD  dwSize = 128; // default size
    CHAR * pszBuf ;

    LogMessage(5,"GetHeader_AutoFree: getting '%s'", variableName);

    if (pfc==NULL)
    {
        // happens in a testing context
        LogMessage(5,"GetHeader_AutoFree: no PFC, returning '%s'", variableName);
        return variableName;
    }
    pszBuf = (char *) pfc->AllocMem(pfc, dwSize, 0);

    //dwSize= 0; // no need to zero this
    fRet= pHeaderInfo->GetHeader(pfc, variableName, pszBuf, &dwSize);
    if (fRet==FALSE) {
        if (GetLastError() == ERROR_INVALID_INDEX)
        {
            // unknown header - return an empty, non-null string
            pszBuf[0]= '\0';
            fRet= TRUE;
            goto GHAF_Finished;
        }
        else if ((GetLastError() != ERROR_INSUFFICIENT_BUFFER) || (dwSize > INTERNET_MAX_URL_LENGTH )) {
            pszBuf = NULL;
            goto GHAF_Finished;
        }

        // AllocMem does request-scoped memory allocation, with auto free. 
        pszBuf= (char *) pfc->AllocMem(pfc, dwSize, 0);
        if ( pszBuf == NULL ) {
            SetLastError( ERROR_NOT_ENOUGH_MEMORY );
            goto GHAF_Finished;
        }
        fRet= pHeaderInfo->GetHeader(pfc, variableName, pszBuf, &dwSize);
        if ( fRet == FALSE )
            goto GHAF_Finished;
    }

 GHAF_Finished:
    if ( fRet == FALSE ) 
        LogMessage(2,"GetHeader_AutoFree failed (GetLastError()=%d)", GetLastError());
    
    LogMessage(5, "GetHeader_AutoFree: %d bytes   ptr:0x%08X", dwSize, pszBuf);
    LogMessage(4, "GetHeader_AutoFree: '%s' = '%s'", variableName, pszBuf);

    return pszBuf;
}


/* This is used only when the IsapiRewriter library is being queried for its version.  */
/* This is never called from the ISAPI itself.  */
/* extern "C" */
char * Iirf_GetVersion() 
{
    return gIirfVersion;
}




/* This is used only when the IsapiRewriter is being driven in the test app.  */
/* This is never called from the ISAPI itself.  */
/* extern "C" */
void IsapiFilterTestSetup(char * psz_iniDirName) 
{
    //char t[_MAX_PATH];
  //printf("IsapiFilterTestSetup\n"); 
    gTesting= TRUE; 

    _makepath_s(IniFileName, _MAX_PATH, NULL, psz_iniDirName, ModuleFname, ".ini");
    _makepath_s(IniFileDirectory, _MAX_PATH, NULL, psz_iniDirName, NULL, NULL);
    //printf("\nnew targett ini file: '%s'\n", IniFileName);

    /*     sprintf(t, "%s\\%s", psz_iniDirName, IniFileName); */
    /*     strncpy(IniFileName, t, _MAX_PATH); */
    /*     strncpy(IniFileDirectory, psz_iniDirName, _MAX_PATH); */

    //strncpy(IniFileName, psz_iniFileName, _MAX_PATH);
    //GetCurrentDirectory(sizeof(IniFileDirectory)/sizeof(IniFileDirectory[0]),
    //IniFileDirectory);

/*     config= ReadConfig(IniFileName,0); */
/*     printf("done reading new config\n"); // to stdout when testing, to nul when used as ISAPI */
/*     if (config == NULL) { */
/*      printf("no config.  Exiting.\n");  */
/*      exit(1); */
/*     } */

    Initialize(); 
}

