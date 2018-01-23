/*

  Extension.c

  part of Ionic's Isapi Rewrite Filter [IIRF]

  Copyright (c) Dino Chiesa, 2005-2010.  All rights reserved.

  ==================================================================

  Licensed under the MS Public License.
  http://opensource.org/licenses/ms-pl.html

  or, see Rewriter.c for the details of the license.

  Last saved:
  Time-stamp: <2011-October-02 17:39:25>

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>     // strftime

#include <HttpExt.h>  // HTTP_FILTER_CONTEXT, etc
#include <WinHttp.h>  // HINTERNET, HTTP_STATUS_OK, etc


#include "IIRF.h"

#define IIPE_EXTENSION_NAME "Ionic ISAPI Proxy Extension (IIPE)"


char *gExtensionVersion= NULL;


// externs
extern char *gIirfVersion;                                                              // Rewriter.c
extern char * gIirfShortVersion;                                                        // Rewriter.c
extern IirfServerConfig * gFilterConfig;                                                // Rewriter.c
extern char * gIirfBuildSig;                                                            // Rewriter.c
extern char *gStyleMarkup;                                                              // Rewriter.c
extern char *gIirfStartupTime;                                                          // Rewriter.c
extern void SetFilterVersionInfo (void);                                                // Rewriter.c
extern CRITICAL_SECTION  gcsVdirConfig;                                                 // Rewriter.c
extern char * Iirf_SystemTimeUtcToLocalTimeString (SYSTEMTIME * pSysTime);              // IirfConfig.c
extern IirfVdirConfig * gVdirConfigList;                                                // IirfConfig.c
extern void LogMessage (IirfVdirConfig * cfg, int MsgLevel, const char * format, ... ); // IirfLogging.c
extern void Iirf_ReleaseArrayWchar (IirfVdirConfig * cfg,  WCHAR** pw);                 // Utils.c
extern WCHAR ** Iirf_wTokenizeAccept (IirfVdirConfig * cfg, CHAR* string);              // Utils.c
extern WCHAR * Iirf_AsciiToWideChar (LPCSTR p);                                         // Utils.c
extern LPSTR Iirf_WideCharToAscii (LPCWSTR w);                                          // Utils.c
extern char * Iirf_AllocAndSprintf (void * ignored, const char * format, ... );         // Utils.c
extern char * Iirf_Rfc1123_DateTimeNow ();                                              // Utils.c
extern BOOL IirfProxy_IsChunkedHeaderPresent(IirfVdirConfig * cfg,                      // Proxy.c
                                             const char *szHeaders);
extern IirfRequestHeader* IirfProxy_ParseAllRaw(IirfVdirConfig * cfg, char * allRaw);   // Proxy.c
extern void IirfProxy_FreeIirfRequestHeaders(IirfRequestHeader * rh);                   // Proxy.c

extern char * IirfProxy_GenProxyRequestHeadersString (IirfVdirConfig * cfg,             // Proxy.c
                                                      IirfRequestHeader *rhRoot,
                                                      char *newHost,
                                                      char *serverName,
                                                      char *localAddr,
                                                      char *remoteAddr,
                                                      DWORD dwTotalSize);
extern char *IirfProxy_GetResponseHeaders (IirfVdirConfig * cfg,                        // Proxy.c
                                           HINTERNET pRequest,
                                           char * localAddr,
                                           char * szStatus,
                                           int status,
                                           char * serverName,
                                           char * port,
                                           char * https);

extern int ExceptionFilter(EXCEPTION_POINTERS *pExp, IirfVdirConfig * cfg);             // ExceptionHandler.cpp
extern void TRACE( char * format, ... );



// forward decls
void SetExtensionVersionInfo(void);
void EmitDirectResponse( LPEXTENSION_CONTROL_BLOCK lpECB);
IirfVdirConfig * GetVdirConfig_FromPath(char * ApplMdPath);
VOID IirfProxy_RelayRequestWithMessageBody( EXTENSION_CONTROL_BLOCK *pECB, IirfVdirConfig * cfg, LPCTSTR fqUrl, LPCTSTR origHost, char * method);
char * GetServerVariable_EX( EXTENSION_CONTROL_BLOCK *pECB, IirfVdirConfig * cfg, char * variableName );





/* GetExtensionVersion
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
BOOL WINAPI GetExtensionVersion( HSE_VERSION_INFO *pVer)
{
    pVer->dwExtensionVersion = HSE_VERSION;
    SetFilterVersionInfo();
    strncpy_s(pVer->lpszExtensionDesc,
              sizeof(pVer->lpszExtensionDesc)/sizeof(pVer->lpszExtensionDesc[0]),
              gIirfVersion,
              HSE_MAX_EXT_DLL_NAME_LEN);
    return TRUE;
}






void ReleaseArrayCharP(IirfVdirConfig * cfg, CHAR** pc)
{
    int i;
    LogMessage(cfg, 5, "ReleaseArrayCharP: pc= 0x%08X", pc);
    if (pc==NULL) return;
    for (i=0; i < 4; i++) {
        LogMessage(cfg, 5, "ReleaseArrayCharP: pc[%d]= 0x%08X", i, pc[i]);
        if (pc[i]!=NULL) free(pc[i]);
    }
    free(pc);
}





// Split a string into 2 or 3 tokens.
// The incoming string is one of two forms:
//    host=foo&path=fruoam&url=as09qw/diewf/ffewsd
//   -or-
//    path=fruoam&url=as09qw/diewf/ffewsd
//
// And the result is an array of tokens:
//    value index
//    ------------
//    host    0
//    path    1
//    url     2
//
CHAR ** SplitPath(const CHAR* string)
{
    //char * StrtokContext= NULL;
    char *p1 = _strdup(string);
    char *amp1 = strchr(p1, '&');
    char *p2 = amp1 ? (amp1+1) : NULL;
    char *amp2 = p2 ? strchr(p2, '&') : NULL;
    char *p3 = NULL;
    CHAR **tokens;
    char *t;
    int form = 0;

    TRACE("SplitPath");

    if (amp1==NULL) {
        // couldn't find the first ampersand
        free(p1);
        return NULL;
    }

    *amp1 = '\0';

    if (_strnicmp(p1, "path=", 5)==0 && _strnicmp(p2, "url=", 4)==0) {
        form = 1;
    }

    else if (_strnicmp(p1, "host=", 5)==0 && _strnicmp(p2, "path=", 5)==0) {
        if (amp2==NULL) {
            free(p1);
            return NULL;
        }
        *amp2 = '\0';
        p3 = (char *)(amp2+1);

        if (_strnicmp(p3, "url=", 4)!=0) {
            free(p1);
            return NULL;
        }
        form = 2;
    }
    else {
        // unexpected args
        free(p1);
        return NULL;
    }

    tokens = (CHAR**) malloc(4 * sizeof(CHAR*));

    if (form == 1) {
        t = strchr(p1, '=');
        tokens[0]= _strdup(t+1);

        t = strchr(p2, '=');
        tokens[1]= _strdup(t+1);
        tokens[2]= NULL;
    }
    else {
        t = strchr(p2, '=');
        tokens[0]= _strdup(t+1);

        t = strchr(p3, '=');
        tokens[1]= _strdup(t+1);

        t = strchr(p1, '=');  // host
        tokens[2]= _strdup(t+1);
    }

    tokens[3]= NULL;
    free(p1);
    return tokens;
}





/* HttpExtensionProc
 *
 * Purpose:
 *
 *     Required entry point for ISAPI Extensions.  This function
 *     is called once, for each request.
 *
 * Arguments:
 *
 *     lpECB - Points to the Extension Control Block
 *
 * Returns:
 *
 *    HSE_STATUS_SUCCESS -- all done
 *    HSE_STATUS_ERROR -- something broke
 *
 */
DWORD WINAPI HttpExtensionProc( LPEXTENSION_CONTROL_BLOCK lpECB )
{
    CHAR* method = NULL;

    TRACE("HttpExtensionProc");

    //method = GetServerVariable_EX(lpECB, NULL, "REQUEST_METHOD");
    method = lpECB->lpszMethod;

    if (_stricmp("GET", method)==0 ||
        _stricmp("TRACE", method)==0 ||
        _stricmp("HEAD", method)==0) {
        // The method will never be GET, HEAD, or TRACE, if the request was
        // rewritten internally by IIRF, in other words, if this is a
        // bonafide request for a proxy transmission.
        // Conclude that the user is just tickling the .iirf extension
        // manually, in which case IIRF should simply emit a diagnostic page.
        EmitDirectResponse(lpECB);
    }
    else {
        char **tokens = SplitPath(lpECB->lpszQueryString);
        if (tokens == NULL) {
            EmitDirectResponse(lpECB);
        }
        else {
            IirfVdirConfig * cfg = NULL;
            cfg = GetVdirConfig_FromPath(tokens[0]);
            __try {
                LogMessage( cfg, 2, "HttpExtensionProc: Proxy to '%s'", tokens[1]);
                IirfProxy_RelayRequestWithMessageBody(lpECB, cfg, tokens[1], tokens[2], method);

                ReleaseArrayCharP(cfg, tokens);

                LogMessage( cfg, 2, "HttpExtensionProc: done");

                // this decrement pairs with an increment on the Filter side.
                InterlockedDecrement(&(cfg->RefCount));
            }
            __except ( ExceptionFilter(GetExceptionInformation(), cfg)) {
            }
        }
    }

    return HSE_STATUS_SUCCESS;
}




/*
 * IirfProxy_RelayRequestWithMessageBody
 *
 * Purpose:
 *
 *   Handles the proxy communication for any HTTP methods, such as PUT or
 *   POST, that require relaying a message body as part of the request.
 *   This fn massages the HTTP request headers, applying the proxy
 *   transformation (via headers and so on), and also reads the message-body
 *   from the original requesting client, and sends that message-body data
 *   to the target server.
 *
 *   It then does the converse with the response, reading from the target
 *   server and sending to the originating client.
 *
 * Arguments:
 *
 *   pECB - pointer to the EXTENSION_CONTROL_BLOCK for the incoming request.
 *      This fn should be called only from IIRF-as-ISAPI-extension.
 *
 *   cfg - IirfVdirConfig, used for logging purposes.
 *
 *   fqUrl - a string, the fully-qualified URL to proxy the request TO.
 *
 *   origHost - a string, the original host. Optionally NULL.
 *      Caller should pass a non-NULL value to implement ProxyPreserveHost.
 *
 *   method - a string, the HTTP method to use. PUT, POST, etc.
 *
 * Returns:
 *
 *
 *
 */

VOID IirfProxy_RelayRequestWithMessageBody(
    EXTENSION_CONTROL_BLOCK *pECB,
    IirfVdirConfig * cfg,
    LPCTSTR fqUrl,
    LPCTSTR origHost,
    char * method)
{
    DWORD            nRetCode          = HTTP_STATUS_OK;
    HINTERNET        hOpen, hConnection, hRequest;
    int              ix                = 0;
    DWORD            bytesRemaining    = 0;
    int              len;
    CHAR*            varRemoteAddr     = GetServerVariable_EX(pECB, cfg, "REMOTE_ADDR");
    CHAR*            varLocalAddr      = GetServerVariable_EX(pECB, cfg, "LOCAL_ADDR");
    CHAR*            varReferer        = GetServerVariable_EX(pECB, cfg, "HTTP_REFERER");
    CHAR*            varUserAgent      = GetServerVariable_EX(pECB, cfg, "HTTP_USER_AGENT");
    CHAR*            varAccept         = GetServerVariable_EX(pECB, cfg, "HTTP_ACCEPT");
    CHAR*            varServerName     = GetServerVariable_EX(pECB, cfg, "SERVER_NAME");
    CHAR*            varAllRaw         = GetServerVariable_EX(pECB, cfg, "ALL_RAW");

    WCHAR *          wReferer          = NULL;
    WCHAR **         pwAccept          = NULL;
    WCHAR            urlDefault[2]     ;
    DWORD            dwOpt             = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    char *           errorStage        = NULL;
    BOOL             bStatus           = FALSE;
    BOOL             isChunked         = FALSE;
    WCHAR *          wUrlPathAndQuery  ;
    WCHAR *          wUrl              = Iirf_AsciiToWideChar(fqUrl);
    WCHAR *          wHostName         = NULL;
    WCHAR *          wUserAgent        = Iirf_AsciiToWideChar(varUserAgent);
    WCHAR *          wMethod           = Iirf_AsciiToWideChar(method);
    WCHAR *          wHeaders          = NULL;
    DWORD            dwRet             = 0;
    DWORD            dwRetLength       = sizeof(DWORD);
    DWORD            dwFlags           = 0;
    URL_COMPONENTS   urlComponents     ;
    int              contentTotalBytes = 0;
    int              contentChunks;
    DWORD            dwTotalLength     = 0;

    LogMessage(cfg, 3,"RelayRequestWithMessageBody: %s", fqUrl);

    urlDefault[0]=L'/';
    urlDefault[1]=L'\0';

    // crack the url
    ZeroMemory(&urlComponents, sizeof(URL_COMPONENTS));
    urlComponents.dwStructSize = sizeof(URL_COMPONENTS);

    // Set required component lengths to non-zero so that they are cracked.
    urlComponents.dwSchemeLength    = -1;
    urlComponents.dwHostNameLength  = -1;
    urlComponents.dwUrlPathLength   = -1;
    urlComponents.dwExtraInfoLength = -1;

    LogMessage(cfg, 2, "RelayRequestWithMessageBody: url(%S)", wUrl);

    if (!WinHttpCrackUrl( wUrl, Iirf_ConvertSizeTo32bits(wcslen(wUrl)), 0, &urlComponents))
    {
        errorStage = "WinHttpCrackUrl";
        goto Proxy2_Fail;
    }

    // Two NOTES about WinHttpCrackUrl:
    //
    // Don't be fooled by the field names in URL_COMPONENTS. The
    // lpszScheme is actually a LPWSTR. It should be named
    // lpwszScheme. The same is true for all the strings
    // in the URL_COMPONENTS structure.
    //
    // Also, when getting the output from WinHttpCrackUrl, and when the
    // length params are non-zero (dwSchemeLength and so on), in the output,
    // the string pointers are not set to allocated buffers. They refer into
    // the original LPWSTR, the URL. You cannot simply access or print out
    // lpszScheme, because in fact the lpszScheme == the original URL - they
    // are the same pointer. In order to get JUST the scheme, you need to copy
    // out the wchar_t's of length dwSchemeLength. Or, terminate the string in
    // place, by doing this: lpszScheme[dwSchemeLength]= L'\0';

    len = urlComponents.dwHostNameLength;
    wHostName = (WCHAR*) malloc((len+1) * sizeof(WCHAR));
    wcsncpy_s(wHostName, len+1, urlComponents.lpszHostName, len);
    wHostName[urlComponents.dwHostNameLength]=L'\0';

    if (urlComponents.nScheme == INTERNET_SCHEME_HTTPS)
        dwFlags |= WINHTTP_FLAG_SECURE;

    wUrlPathAndQuery = (urlComponents.lpszUrlPath[0]==L'\0')
        ? urlDefault
        : urlComponents.lpszUrlPath;

    LogMessage(cfg, 4, "RelayRequestWithMessageBody: host(%S)  path+query(%S)", wHostName, wUrlPathAndQuery);

    dwTotalLength = (pECB->cbTotalBytes == 0xFFFFFFFF)
        ? WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH
        : pECB->cbTotalBytes;

    {
        CHAR * sTargetHost = (origHost == NULL)
            ? Iirf_WideCharToAscii(wHostName)
            : origHost;
        // workitem 30604
        IirfRequestHeader * rhRoot = IirfProxy_ParseAllRaw(cfg, varAllRaw);
        CHAR * sHeaders =
            IirfProxy_GenProxyRequestHeadersString(cfg, rhRoot, sTargetHost, varServerName, varLocalAddr, varRemoteAddr, dwTotalLength);
        wHeaders= Iirf_AsciiToWideChar(sHeaders);
        free(sHeaders);
        if (origHost == NULL) free (sTargetHost);
        IirfProxy_FreeIirfRequestHeaders(rhRoot);
    }

    //DebugBreak();
    hOpen = WinHttpOpen(wUserAgent,
                        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                        WINHTTP_NO_PROXY_NAME,
                        WINHTTP_NO_PROXY_BYPASS,
                        0);
    if (hOpen == NULL) {
        errorStage = "WinHttpOpen";
        goto Proxy2_Fail;
    }

    if (!WinHttpSetOption(hOpen, WINHTTP_OPTION_REDIRECT_POLICY, &dwOpt, sizeof(DWORD))) {
        errorStage = "WinHttpSetOption";
        goto Proxy2_Fail;
    }

    if (!WinHttpSetTimeouts(hOpen,
                            cfg->ProxyTimeout[0]*1000, // dwResolveTimeout
                            cfg->ProxyTimeout[1]*1000, // dwConnectTimeout
                            cfg->ProxyTimeout[2]*1000, // dwSendTimeout
                            cfg->ProxyTimeout[3]*1000  // dwReceiveTimeout
            )) {
        errorStage = "WinHttpSetTimeouts";
        goto Proxy2_Fail;
    }

    LogMessage(cfg, 4, "RelayRequestWithMessageBody: varAccept 0x%08X (%s)",
               varAccept,
               (varAccept==NULL)? "-null-" : varAccept);

    pwAccept= Iirf_wTokenizeAccept(cfg, varAccept);

    wReferer = (varReferer[0]=='\0')
        ? WINHTTP_NO_REFERER
        : Iirf_AsciiToWideChar(varReferer);


    LogMessage(cfg, 4, "RelayRequestWithMessageBody: WinHttpConnect %S %d", wHostName, urlComponents.nPort);

    hConnection = WinHttpConnect(hOpen, wHostName, urlComponents.nPort, 0);
    if (hConnection == NULL) {
        errorStage = "WinHttpConnect";
        goto Proxy2_Fail;
    }

    LogMessage(cfg, 4, "RelayRequestWithMessageBody: WinHttpOpenRequest %s %S", method, urlComponents.lpszUrlPath);
    hRequest = WinHttpOpenRequest(hConnection,
                                  wMethod,
                                  urlComponents.lpszUrlPath,
                                  L"HTTP/1.1",
                                  wReferer,
                                  pwAccept,
                                  dwFlags);   // maybe secure
    if (hRequest == NULL) {
        errorStage = "WinHttpOpenRequest";
        goto Proxy2_Fail;
    }

    LogMessage(cfg, 4, "RelayRequestWithMessageBody: WinHttpAddRequestHeaders");

    if (! WinHttpAddRequestHeaders(hRequest, wHeaders, -1L, WINHTTP_ADDREQ_FLAG_ADD)) {
        errorStage = "WinHttpAddRequestHeaders";
        goto Proxy2_Fail;
    }

    // Now, send the request, including any POST data.
    // This data may be large.


    // http://msdn.microsoft.com/en-us/library/aa384110%28VS.85%29.aspx
    // -------------------------------------------------------
    // Starting in Windows Vista and Windows Server 2008, WinHttp
    // enables applications to perform chunked transfer encoding on
    // data sent to the server. When the Transfer-Encoding header is
    // present on the WinHttp request, the dwTotalLength parameter
    // in the call to WinHttpSendRequest is set to
    // WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH and the application sends
    // the entity body in one or more calls to WinHttpWriteData. The
    // lpOptional parameter of WinHttpSendRequest must be NULL and
    // the dwOptionLength parameter must be zero, otherwise an
    // ERROR_WINHTTP_INVALID_PARAMETER error is returned. To
    // terminate the chunked data transfer, the application
    // generates a zero length chunk and sends it in the last call
    // to WinHttpWriteData.

    // http://msdn.microsoft.com/en-us/library/aa384110(VS.85).aspx
    // workitem 25950

    LogMessage(cfg, 4, "RelayRequestWithMessageBody: WinHttpSendRequest  totalLength(%d/%d)", pECB->cbTotalBytes, dwTotalLength);

    if (! WinHttpSendRequest(hRequest,
                             WINHTTP_NO_ADDITIONAL_HEADERS, // addl hdrs to append
                             0,                             // length of those headers
                             NULL,                          // lpOptional == optional request data
                             0,                             // dwOptionalLength
                             dwTotalLength,                 // dwTotalLength - total we are going to send
                             (DWORD_PTR)NULL)               // dwContext

        && GetLastError() != ERROR_IO_PENDING) {
        errorStage = "WinHttpSendRequest";
        goto Proxy2_Fail;
    }

    // If there's data available, write it.
    if (pECB->cbAvailable > 0) {
        DWORD bytesWritten;
        if (! WinHttpWriteData(hRequest,
                               pECB->lpbData,     // lpBuffer
                               pECB->cbAvailable, // dwNumberOfBytesToWrite
                               &bytesWritten)) {  // lpdwNumberOfBytesWritten
            errorStage = "WinHttpWriteData";
            goto Proxy2_Fail;
        }

        LogMessage(cfg, 4, "RelayRequestWithMessageBody: WinHttpWriteData  available(%d) written(%d)",
                   pECB->cbAvailable, bytesWritten);
    }

    // If more to write, do so.
    if ((dwTotalLength == 0) || ((bytesRemaining = pECB->cbTotalBytes - pECB->cbAvailable) > 0)) {
        DWORD bytesWritten;
        DWORD bufSize = 1024*8;  // read page in 8k chunks
        CHAR * buffer = (CHAR *) malloc(bufSize);
        DWORD dwSize = bufSize;

        LogMessage(cfg, 4, "RelayRequestWithMessageBody: more to write  remaining(%d)",
                   bytesRemaining);

        contentChunks= 0;

        while (((dwTotalLength == 0 && dwSize > 0) ||
                (dwTotalLength > 0 && bytesRemaining > 0)) &&
               (contentChunks < IIRF_PROXY_MAX_CHUNKS_TO_READ)) {
            // first, read
            dwSize = bufSize;
            if (! pECB->ReadClient(pECB->ConnID, buffer, &dwSize)) {
                errorStage = "ReadClient";
                free(buffer);
                goto Proxy2_Fail;
            }
            LogMessage(cfg, 5, "RelayRequestWithMessageBody: ReadClient  sz(%d)", dwSize);

            if (dwSize > 0) {
                // then write
                if (! WinHttpWriteData(hRequest, buffer, dwSize, &bytesWritten)) {
                    errorStage = "WinHttpWriteData2";
                    free(buffer);
                    goto Proxy2_Fail;
                }

                LogMessage(cfg, 5, "RelayRequestWithMessageBody: WinHttpWriteData  sz(%d)", bytesWritten);
                contentChunks++;
                bytesRemaining -= dwSize;
            }
        }

        LogMessage(cfg, 4, "RelayRequestWithMessageBody: ReadClient/WriteData chunks(%d) totalBytes(%d)",
                   contentChunks, pECB->cbTotalBytes);

        free(buffer);
        if (contentChunks < IIRF_PROXY_MAX_CHUNKS_TO_READ)
            SetLastError( NO_ERROR );
        else {
            errorStage = "ReadClient/WriteData";
            SetLastError( ERROR_IO_INCOMPLETE );
        }
    }

    LogMessage(cfg, 4, "RelayRequestWithMessageBody: WinHttpReceiveResponse");

    // Wait for the request to complete.
    if (!WinHttpReceiveResponse( hRequest, NULL)) {
        if (GetLastError() == ERROR_WINHTTP_TIMEOUT)
            nRetCode = HTTP_STATUS_REQUEST_TIMEOUT+10000;
        else
            LogMessage(cfg, 1, "RelayRequestWithMessageBody: Error in WinHttpReceiveResponse(): %d", GetLastError());
    }
    else {
        LogMessage(cfg, 5, "RelayRequestWithMessageBody: WinHttpQueryHeaders");
        // Get the Status Code
        if (! WinHttpQueryHeaders(hRequest,
                                  WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                  WINHTTP_HEADER_NAME_BY_INDEX,
                                  &dwRet,
                                  &dwRetLength,
                                  WINHTTP_NO_HEADER_INDEX)) {
            errorStage = "WinHttpQueryHeaders";
            goto Proxy2_Fail;
        }
        nRetCode = dwRet;
        LogMessage(cfg, 4, "RelayRequestWithMessageBody: WinHttpQueryHeaders: status %d", nRetCode);
    }

    {
        CHAR szStatus[32];
        HSE_SEND_HEADER_EX_INFO info;
        char *sRawHeaders = NULL;
        DWORD rc1;
        char * port = NULL;
        char * https = NULL;
        if (cfg->rootPpr != NULL) {
            // need these only if ProxyPassReverse directive is present
            port = GetServerVariable_EX(pECB, cfg, "SERVER_PORT");
            https = GetServerVariable_EX(pECB, cfg, "HTTPS");
        }
        ZeroMemory(szStatus, 32);

        sRawHeaders= IirfProxy_GetResponseHeaders(cfg, hRequest, varLocalAddr, szStatus, nRetCode, varServerName, port, https);

        if (port!=NULL) free (port);
        if (https!=NULL) free (https);

        // workitem 25703
        isChunked = IirfProxy_IsChunkedHeaderPresent(cfg, sRawHeaders);

        LogMessage(cfg, 4, "RelayRequestWithMessageBody: HSE_REQ_SEND_RESPONSE_HEADER_EX szStatus %s", szStatus);

        info.pszStatus = szStatus;
        info.pszHeader = sRawHeaders;
        info.cchStatus = Iirf_ConvertSizeTo32bits(strlen(szStatus));
        info.cchHeader = (sRawHeaders) ? Iirf_ConvertSizeTo32bits(strlen(sRawHeaders)) : 0;
        info.fKeepConn = FALSE;  // TRUE ??

        // Send header back to client.
        // http://msdn.microsoft.com/en-us/library/ms524709.aspx

        rc1 = pECB->ServerSupportFunction(
            pECB->ConnID,
            HSE_REQ_SEND_RESPONSE_HEADER_EX,
            &info,
            NULL,  // unused
            NULL   // unused
            );

        if (sRawHeaders) free(sRawHeaders);

        if (!rc1) {
            errorStage = "WinHttpQueryHeaders";
            goto Proxy2_Fail;
        }
    }


    if (nRetCode != HTTP_STATUS_REQUEST_TIMEOUT &&
        nRetCode != HTTP_STATUS_REQUEST_TIMEOUT+10000) {
        DWORD nRead = 0l;
        DWORD nWritten;
        int dwSize= 0;
        int bufSize = IIRF_PROXY_CHUNK_SIZE; // TODO: make this size configurable.
        CHAR * buffer = (CHAR *) malloc(bufSize);
        char szbuf[16];  // for the chunk frame data

        contentChunks= 0;

        do {
            LogMessage(cfg, 5, "RelayRequestWithMessageBody: WinHttpQueryDataAvailable");
            dwSize = 0;
            if (!WinHttpQueryDataAvailable( hRequest, &dwSize)) {
                errorStage = "WinHttpQueryDataAvailable";
                goto Proxy2_Fail;
            }
            nRead = 0l;
            if (dwSize>0) {
                int sizeToRead = (dwSize > bufSize-2)? bufSize-2 : dwSize;
                LogMessage(cfg, 5, "RelayRequestWithMessageBody: WinHttpReadData %d", sizeToRead);
                if (!WinHttpReadData(hRequest, buffer, sizeToRead, &nRead)) {
                    errorStage = "WinHttpReadData";
                    goto Proxy2_Fail;
                }
                LogMessage(cfg, 5, "RelayRequestWithMessageBody: WinHttpReadData nRead= %d", nRead);
                if (nRead > 0l) {
                    // workitem 25703
                    if (isChunked) {
                        // the start frame for this chunk
                        sprintf_s(szbuf, sizeof(szbuf)/sizeof(szbuf[0]), "%0x\r\n", nRead);
                        nWritten = Iirf_ConvertSizeTo32bits(strlen(szbuf));
                        pECB->WriteClient(pECB->ConnID, szbuf, &nWritten, 0);
                    }

                    // the data for the chunk
                    nWritten = nRead;
                    pECB->WriteClient(pECB->ConnID, buffer, &nWritten, 0);

                    if (isChunked) {
                        // the end frame for this chunk
                        nWritten = 2;
                        pECB->WriteClient(pECB->ConnID, "\r\n", &nWritten, 0);
                    }

                    contentTotalBytes += nRead;
                    contentChunks++;
                }
            }
        } while((nRead > 0) && (contentChunks < IIRF_PROXY_MAX_CHUNKS_TO_READ));

        if (isChunked) {
            // the final, zero-length chunk
            sprintf_s(szbuf, sizeof(szbuf)/sizeof(szbuf[0]), "0\r\n\r\n");
            nWritten = Iirf_ConvertSizeTo32bits(strlen(szbuf));
            pECB->WriteClient(pECB->ConnID, szbuf, &nWritten, 0);
        }

        LogMessage(cfg, 4, "RelayRequestWithMessageBody: ReadData/WriteClient chunks(%d) totalBytes(%d)",
                   contentChunks, contentTotalBytes);

        free(buffer);
        if (contentChunks < IIRF_PROXY_MAX_CHUNKS_TO_READ)
            SetLastError( NO_ERROR );
        else {
            errorStage = "ReadData/WriteClient";
            SetLastError( ERROR_IO_INCOMPLETE );
        }
    }

Proxy2_Fail:
    if (errorStage)
        LogMessage(cfg, 1, "IirfProxy_RelayRequestWithMessageBody: Error in %s: %d", errorStage, GetLastError());

    if (hRequest != NULL)    WinHttpCloseHandle(hRequest);
    if (hConnection != NULL) WinHttpCloseHandle(hConnection);
    if (hOpen != NULL)       WinHttpCloseHandle(hOpen);

    if (varRemoteAddr!=NULL) free (varRemoteAddr);
    if (varLocalAddr!=NULL)  free (varLocalAddr);
    if (varReferer!=NULL)    free (varReferer);
    if (varUserAgent!=NULL)  free (varUserAgent);
    if (varAccept!=NULL)     free (varAccept);
    if (varServerName!=NULL) free (varServerName);
    if (varAllRaw!=NULL)     free (varAllRaw);

    if (wReferer)    free(wReferer);
    if (pwAccept)    Iirf_ReleaseArrayWchar(cfg, pwAccept);
    if (wHostName)   free(wHostName);

    if (wUrl)        free(wUrl);
    if (wHeaders)    free(wHeaders);
    if (wUserAgent)  free(wUserAgent);
    if (wMethod)     free(wMethod);
}



BOOL WINAPI TerminateExtension(DWORD dwFlags)
{
    /* now is the chance to free / unload / unlock any
     * allocated/loaded/locked resources */
    return TRUE;
}



void EmitDirectResponse( LPEXTENSION_CONTROL_BLOCK lpECB)
{
    char * rawHeaders = NULL;
    char * szDate = Iirf_Rfc1123_DateTimeNow();
    HSE_SEND_HEADER_EX_INFO info;
    char *method = lpECB->lpszMethod;

    TRACE("EmitDirectResponse");

    if (_stricmp(method, "GET")==0 || _stricmp(method, "HEAD")==0) {
        SYSTEMTIME stRightNow ;
        char * rightNow = NULL;
        char * pageHeader = NULL;
        char * pageContent = NULL;
        DWORD dwBytes = 0;

        if (gIirfStartupTime == NULL)
            gIirfStartupTime = Iirf_SystemTimeUtcToLocalTimeString(&(gFilterConfig->StartupTime));

        GetSystemTime(&(stRightNow));
        rightNow = Iirf_SystemTimeUtcToLocalTimeString(&stRightNow);

        pageHeader = Iirf_AllocAndSprintf(NULL,
                                          "<html>\n  <head>\n"
                                          "%s"
                                          "  </head>\n",
                                          gStyleMarkup);

        pageContent = Iirf_AllocAndSprintf(NULL,
                                           "<body><h2>IIRF Proxy Extension</h2>\r\n"
                                           "<p>You've apparently invoked the IIRF Proxy Extension, directly.</p>\r\n"
                                           "<p>The .iirf extension is intended to be used only by IIRF itself.</p>\r\n"
                                           "<table border='1px'>\n"
                                           "<tr><th>IIRF Version</th><td>%s</td></tr>\r\n"
                                           "<tr><th>Built</th><td>%s</td></tr>\r\n"
                                           "<tr><th>Started</th><td>%s</td></tr>\r\n"
                                           "<tr><th>Current Time</th><td>%s</td></tr>\r\n"
                                           "</table>\r\n</body>\r\n</html>",
                                           gIirfVersion,
                                           gIirfBuildSig,
                                           gIirfStartupTime,
                                           rightNow);

        // write the HTTP Headers
        rawHeaders = Iirf_AllocAndSprintf(NULL,
                                          "Date: %s\r\n"
                                          "Content-Type: text/html; charset=utf-8\r\n"
                                          "X-Powered-By: %s\r\n"
                                          "Content-Length: %d\r\n"
                                          "Connection: Close\r\n\r\n",
                                          szDate,
                                          gIirfShortVersion,
                                          strlen(pageHeader) + strlen(pageContent));

        info.pszStatus = "200";
        info.pszHeader = rawHeaders;
        info.cchStatus = Iirf_ConvertSizeTo32bits(strlen(info.pszStatus));
        info.cchHeader = (rawHeaders) ? Iirf_ConvertSizeTo32bits(strlen(rawHeaders)) : 0;
        info.fKeepConn = FALSE;

        // Send header to client.
        lpECB->ServerSupportFunction(lpECB->ConnID,
                                     HSE_REQ_SEND_RESPONSE_HEADER_EX,
                                     &info,
                                     NULL,    // unused
                                     NULL);   // unused

        // send the message body only if not a HEAD request
        if (_stricmp(method, "HEAD")!=0) {
            dwBytes = Iirf_ConvertSizeTo32bits(strlen(pageHeader));
            lpECB->WriteClient(lpECB->ConnID, pageHeader, &dwBytes, 0);
            dwBytes = Iirf_ConvertSizeTo32bits(strlen(pageContent));
            lpECB->WriteClient(lpECB->ConnID, pageContent, &dwBytes, 0);
        }
        free(rightNow);
        free(pageHeader);
        free(pageContent);
    }

    else if (_stricmp(method, "TRACE")==0) {

        // reflect the incoming request.
        // see http://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html#sec9.8
        DWORD dwBytes = 0;
        char * allraw = GetServerVariable_EX(lpECB, NULL, "ALL_RAW");
        char * reqUrl = GetServerVariable_EX(lpECB, NULL, "HTTP_URL");
        char * reqHttpVersion = GetServerVariable_EX(lpECB, NULL, "HTTP_VERSION");
        char * pageContent = Iirf_AllocAndSprintf(NULL,
                                                  "%s %s %s\r\n%s",
                                                  method,
                                                  reqUrl,
                                                  reqHttpVersion,
                                                  allraw);

        rawHeaders = Iirf_AllocAndSprintf(NULL,
                                          "Date: %s\r\n"
                                          "Content-Type: message/http\r\n"
                                          "X-Powered-By: %s\r\n"
                                          "Content-Length: %d\r\n\r\n",
                                          szDate,
                                          gIirfShortVersion,
                                          strlen(pageContent));

        info.pszStatus = "200";
        info.pszHeader = rawHeaders;
        info.cchStatus = Iirf_ConvertSizeTo32bits(strlen(info.pszStatus));
        info.cchHeader = Iirf_ConvertSizeTo32bits(strlen(rawHeaders));
        info.fKeepConn = FALSE;

        // Send response to client.
        lpECB->ServerSupportFunction(lpECB->ConnID,
                                     HSE_REQ_SEND_RESPONSE_HEADER_EX,
                                     &info,
                                     NULL,    // unused
                                     NULL);   // unused

        dwBytes = Iirf_ConvertSizeTo32bits(strlen(pageContent));
        lpECB->WriteClient(lpECB->ConnID, pageContent, &dwBytes, 0);

        free(allraw);
        free(reqUrl);
        free(reqHttpVersion);
        free(pageContent);
    }

    else if (_stricmp(method, "OPTIONS")==0) {

        // NB: The set of options (Verbs) published here does not need to
        // agree with the set enabled in the ISAPI Extension install, which
        // is done in Extension_CA.vbs in the installer logic. For external
        // clients, we want to handle only OPTIONS, HEAD, TRACE, and GET.  POST,
        // PUT, and other verbs are also handled by this extension, but such
        // requests are expected to come only from an IIRF rewrite.

        // write the HTTP Headers
        rawHeaders = Iirf_AllocAndSprintf(NULL,
                                          "Date: %s\r\n"
                                          "Allow: OPTIONS, GET, HEAD, TRACE\r\n"
                                          "Content-Length: 0\r\n\r\n",
                                          szDate);

        info.pszStatus = "200";
        info.pszHeader = rawHeaders;
        info.cchStatus = Iirf_ConvertSizeTo32bits(strlen(info.pszStatus));
        info.cchHeader = Iirf_ConvertSizeTo32bits(strlen(rawHeaders));
        info.fKeepConn = FALSE;

        // Send response to client.
        lpECB->ServerSupportFunction(lpECB->ConnID,
                                     HSE_REQ_SEND_RESPONSE_HEADER_EX,
                                     &info,
                                     NULL,    // unused
                                     NULL);   // unused
    }

    else {
        // unknown request...
        static const char * hdrFormat =
            "Date: %s\r\n"
            "X-Powered-By: %s\r\n\r\n";

        rawHeaders = Iirf_AllocAndSprintf(NULL,
                                          hdrFormat, szDate, gIirfShortVersion);

        info.pszStatus = "405"; // not allowed
        info.pszHeader = rawHeaders;
        info.cchStatus = Iirf_ConvertSizeTo32bits(strlen(info.pszStatus));
        info.cchHeader = Iirf_ConvertSizeTo32bits(strlen(rawHeaders));
        info.fKeepConn = FALSE;

        // Send headers to client.
        lpECB->ServerSupportFunction(lpECB->ConnID,
                                     HSE_REQ_SEND_RESPONSE_HEADER_EX,
                                     &info,
                                     NULL,    // unused
                                     NULL);   // unused
    }

    if (rawHeaders) free(rawHeaders);
    free(szDate);
}



IirfVdirConfig * GetVdirConfig_FromPath(char * ApplMdPath)
{
    IirfVdirConfig * current;

    //TRACE("GetVdirConfig");

    // Prevent potential updates to the list while scanning it, using the
    // CRITICAL_SECTION.  We just use one coarse-grained lock.  We *could*
    // optimize to use a reader-writer lock with upgrades, but that is for
    // another day.
    EnterCriticalSection(&gcsVdirConfig);
    current = gVdirConfigList;
    // see if we can find a match in the stack:
    while (current != NULL) {
        if (strcmp(current->ApplMdPath, ApplMdPath)==0) {

            LeaveCriticalSection(&gcsVdirConfig);
            LogMessage( current, 4, "GetVdirConfig_FromPath: Obtain  site '%s' (era=%d) (rc=%d) (Expired=%d) (ptr=0x%08X)...",
                        current->ApplMdPath,
                        current->Era,
                        current->RefCount,
                        current->Expired,
                        current);
            return current;
        }
        current = current->Next;
    }

    LeaveCriticalSection(&gcsVdirConfig);
    return NULL;
}





/*
 * GetServerVariable_EX
 *
 * Purpose:
 *
 *     Get a server variable, from within the ISAPI extension.
 *
 * Arguments:
 *
 *     pECB - pointer to the EXTENSION_CONTROL_BLOCK for the current request.
 *
 *     cfg - the IirfVdirConfig that is applicable. In a testing scenario, this
 *          can be NULL.
 *
 *     variableName - name of the variable to retrieve.
 *
 * Returns:
 *
 *     malloc'd string containing the value. If non-NULL, caller must free.
 *     In the case of an unknown variable, the value is a string containing
 *     the name of the variable. In this case it should still be free'd.
 *
 */
char * GetServerVariable_EX (EXTENSION_CONTROL_BLOCK *pECB,
                             IirfVdirConfig * cfg,
                             char * variableName )
{
    BOOL   fRet = FALSE;
    CHAR * pszBuf = (CHAR *) malloc(SERVER_VAR_BUFFER_SIZE_DEFAULT);
    int    cbBuf = SERVER_VAR_BUFFER_SIZE_DEFAULT;

    if (cfg != NULL)
        LogMessage(cfg, 5,"GetServerVariable_EX: getting '%s'", variableName);

    if ( pszBuf == NULL ) {
        SetLastError( ERROR_NOT_ENOUGH_MEMORY );
        goto GSV3_Finished;
    }

    pszBuf[0]='\0';
    fRet = pECB->GetServerVariable( pECB->ConnID, variableName, pszBuf, &cbBuf );

    if ( fRet == FALSE ) {
        if ( GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            // The buffer is not large enough.
            if (cfg != NULL)
                LogMessage(cfg, 5, "GetServerVariable_EX: initial buffer is not large enough.");

            // is the required size within the configured limit?
            if (cbBuf > gFilterConfig->MaxFieldLength ) {
                if (cfg != NULL)
                    LogMessage(cfg, 1, "** ERROR: the required buffer size (%d) exceeds the limit (%d)",
                               cbBuf, gFilterConfig->MaxFieldLength );
                SetLastError( ERROR_BAD_LENGTH );
                goto GSV3_Finished;
            }

            // Reallocate the buffer.
            free(pszBuf);
            pszBuf = (CHAR *) malloc(cbBuf);
            if ( pszBuf == NULL ) {
                SetLastError( ERROR_NOT_ENOUGH_MEMORY );
                goto GSV3_Finished;
            }

            pszBuf[0]='\0';
            fRet = pECB->GetServerVariable( pECB->ConnID, variableName, pszBuf, &cbBuf );

            if ( fRet == FALSE ) {
                if (cfg != NULL)
                    LogMessage(cfg, 1,"** ERROR: GetServerVariable_EX failed.");
                //
                // Unexpected failure. Bail.
                //
                strcpy_s(pszBuf,cbBuf,variableName);
            }
        }
        else if ( GetLastError() == ERROR_INVALID_INDEX ) {
            //
            // Did not find the named Server Variable.
            //
            if (cfg != NULL)
                LogMessage(cfg, 2, "GetServerVariable_EX: does not exist (%s)", variableName );

            strcpy_s(pszBuf, SERVER_VAR_BUFFER_SIZE_DEFAULT, variableName);
        }
        else {
            if (cfg != NULL)
                LogMessage(cfg, 3, "GetServerVariable_EX: ???");
            strcpy_s(pszBuf, SERVER_VAR_BUFFER_SIZE_DEFAULT, variableName);
        }
    }

GSV3_Finished:
    // this stanza for logging only
    if (cfg != NULL) {
        LogMessage(cfg, 5, "GetServerVariable_EX: %d bytes", cbBuf);
        LogMessage(cfg, 5, "GetServerVariable_EX: result '%s'", pszBuf);
    }

    //
    // At this point, pszBuf points to the variable value and
    // cbBuf indicates size of buffer, including terminating NULL.
    //

    return pszBuf;
}


