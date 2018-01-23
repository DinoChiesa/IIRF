/*

  Utils.c

  part of Ionic's Isapi Rewrite Filter [IIRF]

  Copyright (c) Dino Chiesa 2005-2010.
  All rights reserved.

  ==================================================================

  Licensed under the MS Public License.
  http://opensource.org/licenses/ms-pl.html

  See the attached License.txt file, or see the Rewriter.c module for
  the details of the license for IIRF.

  Last saved: <2012-March-11 19:46:52>

 */


#include <WTypes.h>    // DWORD, WCHAR, etc
#include <time.h>      // gmtime, tm
#include <HttpFilt.h>  // HTTP_FILTER_CONTEXT, etc
#include <intsafe.h>   // INT32_MAX

#include "Iirf.h"

static const char *DAY_NAMES[] =
      { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

static const char *MONTH_NAMES[] =
      { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

/*
 * Iirf_Rfc1123_DateTimeNow
 *
 * Purpose:
 *
 *     Produce an RFC 1123-compliant date string, corresponding
 *     to the current time.
 *
 * Returns:
 *
 *     malloc'd string containing RFC1123-compliant date string.
 *     caller must free.
 *
 */
char *Iirf_Rfc1123_DateTimeNow()
{
    const int RFC1123_TIME_LEN = 30;
    time_t t;
    struct tm tm;
    char * buf = malloc(RFC1123_TIME_LEN+2);

    time(&t);
    gmtime_s(&tm, &t);

    strftime(buf, RFC1123_TIME_LEN, "---, %d --- %Y %H:%M:%S GMT", &tm);
    memcpy(buf, DAY_NAMES[tm.tm_wday], 3);
    memcpy(buf+8, MONTH_NAMES[tm.tm_mon], 3);

    return buf;
}



char * Iirf_AllocAndSprintf( HTTP_FILTER_CONTEXT * pfc, const char * format, ... )
{
    va_list args;
    char * messageBuffer;
    int len;
    va_start( args, format );
    len = _vscprintf( format, args ) + 1; // _vscprintf doesn't count terminating '\0'

    messageBuffer = (pfc!=NULL)
        ? (char *) pfc->AllocMem(pfc, sizeof(char) * (len+1), 0)
        : (char *) malloc(sizeof(char) * (len+1));

    vsprintf_s( messageBuffer, len, format, args );
    va_end(args);
    return messageBuffer;
}



BOOL Iirf_FileExists(const TCHAR *fileName)
{
    DWORD fileAttr = GetFileAttributes(fileName);
    if (0xFFFFFFFF == fileAttr)
        return FALSE;
    return TRUE;
}


void Iirf_EmitEventLogEvent(WORD infoType, DWORD dwEventId, LPTSTR msg1, LPTSTR msg2)
{
    HANDLE hEventSource = RegisterEventSource(NULL, TEXT("Ionic Isapi Rewriting Filter"));
    if (hEventSource != NULL) {
        LPCTSTR lpsz[3];
        const char * format = "IIRF: event ID %d";
        size_t len = _scprintf(format, dwEventId) + 1;
        char  *msg = malloc(sizeof(char) * len);

        if (msg!= NULL) {
            sprintf_s(msg, len, format, dwEventId);
            lpsz[0] = msg;
            lpsz[1] = msg1;
            lpsz[2] = msg2;

            ReportEvent(hEventSource,
                        infoType,       // EVENTLOG_{INFORMATION,WARNING,ERROR}_TYPE, etc
                        0,              // category (event source specific)
                        dwEventId,      // specific to the event source
                        NULL,           // user SID (NULL is ok)
                        (msg2==NULL?2:3), /// number of strings
                        0,              // number of bytes of raw data
                        lpsz,           // array of strings
                        NULL);          // the raw data

            DeregisterEventSource(hEventSource);
            free(msg);
        }
    }
}


void Iirf_EmitEventLogEventX( WORD infoType, DWORD dwEventId, LPTSTR msg2, const char * format, ... )
{
    va_list args;
    int len;
    char *msg1;
    va_start( args, format );
    len = _vscprintf( format, args ) + 1; // add one for the terminator
    msg1= malloc( len * sizeof(char) );
    vsprintf_s( msg1, len, format, args );
    va_end(args);
    Iirf_EmitEventLogEvent(infoType, dwEventId, msg1, msg2);
    free( msg1 );
}



#ifdef _WIN64
DWORD Iirf_ConvertSizeTo32bitsImpl(size_t sz, char *file, int line)
{
    if (!(0 <= sz && sz <= INT32_MAX)) {
        // log message
        Iirf_EmitEventLogEventX(EVENTLOG_ERROR_TYPE, IIRF_EVENT_INVALID_PARAM, NULL,
                           "Invalid Pointer size: %d file(%s) line(%d)",
                                                   sz,
                           file, line);

        ExitProcess( 0 );
    }
    return (DWORD) sz;
}
#endif


char * Iirf_IsapiStrdup( HTTP_FILTER_CONTEXT * pfc, const char * source)
{
    int len = Iirf_ConvertSizeTo32bits(strlen(source) + 1);
    char *newString = pfc->AllocMem(pfc, sizeof(char) * len, 0);
    strcpy_s(newString,len,source);
    return newString;
}



/* Iirf_AllocAndConcatenate
 *
 * Purpose:
 *
 *    Allocates enough space to concatenate 2 strings, and returns the
 *    concatenation of those strings.
 *
 * Returns:
 *
 *    A newly-allocated string. It must be freed.
 */
char *Iirf_AllocAndConcatenate(char *s1, char *s2)
{
    size_t len= strlen(s1) + strlen(s2) + 1;
    char *newString = malloc(sizeof(char) * len);
    strcpy_s(newString, len, s1);
    strcat_s(newString, len, s2);
    return newString;
}


WCHAR * Iirf_AsciiToWideChar(LPCSTR p)
{
    DWORD len = Iirf_ConvertSizeTo32bits(strlen(p));
    LPWSTR p2 = (WCHAR *) malloc(sizeof(WCHAR) * (len+1));
    ZeroMemory(p2, sizeof(WCHAR) * (len+1));
    if (0 == MultiByteToWideChar(CP_ACP, 0, p, len, p2, len*2)) {
        // FAIL
        free(p2);
        p2 = NULL;
    }
    else p2[len]=L'\0';
    return p2;
}

LPSTR Iirf_WideCharToAscii(LPCWSTR w)
{
    int len2= lstrlenW(w);
    char *s = (char *) malloc(len2+1);
    //fprintf(stderr,"U2A: alloc %d bytes\n", len2);
    ZeroMemory(s, len2+1);
    if (0 == WideCharToMultiByte(CP_ACP, 0, w, len2, s, len2, NULL, NULL)) {
        // FAIL
        free(s);
        s = NULL;
    }
    else s[len2]='\0';
    return s;
}



WCHAR ** Iirf_wTokenizeAccept (IirfVdirConfig * cfg, const CHAR* string)
{
    const char *p;
    WCHAR **w;
    char *p2;
    int c=0, i=0;

    //LogMessage(cfg, 1, "wTokenizeAccept: string(%s)", string);

    // Need two passes: first to count the items, second to
    // allocate the pointers.

    p= string;
    while (p!=NULL) {
        c++;
        p= strchr(p+1, ',');
    }
    c++;
    w = (WCHAR**) malloc(c * sizeof(WCHAR*));
    //LogMessage(cfg, 1, "wTokenizeAccept: malloc w(0x%08X) c(%d)", w, c);

    p= string;
    while (p!=NULL)
    {
        p2= strchr(p, ',');
        if (p2!=NULL)
        {
            *p2=0;
            w[i]= Iirf_AsciiToWideChar(p);
            *p2=',';
            p = p2+1;
        }
        else
        {
            // the final one
            w[i]= Iirf_AsciiToWideChar(p);
            p = p2;
        }
        //LogMessage(cfg, 1, "wTokenizeAccept:    w[%d]= 0x%08X (%S)", i, w[i], w[i]);
        i++;
    }

    w[i]=NULL;
    //LogMessage(cfg, 1, "wTokenizeAccept: zero i(%d)", i);
    return w;
}


void Iirf_ReleaseArrayWchar( IirfVdirConfig * cfg, WCHAR** pw)
{
    int i;
    //LogMessage(cfg, 5, "ReleaseArrayWchar: pw=    0x%08X", pw);
    if (pw==NULL)
        return;

    for (i=0; pw[i]!=NULL; i++)
    {
        //LogMessage(cfg, 5, "ReleaseArrayWchar: pw[%d]= 0x%08X", i, pw[i]);
        free(pw[i]);
    }
    free(pw);
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
    char *result = malloc(sz);
    int rc;
    SystemTimeToTzSpecificLocalTime(NULL, pSystemTime, &stLocal);
    rc= GetTimeZoneInformation(&tzi);
    if (rc==1 || rc==2) {
        LPCWSTR wszTz= (rc==1)? tzi.StandardName:tzi.DaylightName;
        rc = WideCharToMultiByte(
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

    sprintf_s(result, sz, "%d/%02d/%02d %02d:%02d:%02d %s",
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
    if ( pFileTime->dwLowDateTime ==0 && pFileTime->dwHighDateTime == 0) {
        return (char *) _strdup("(file not found)");
    }
    else {
        SYSTEMTIME stUtc;
        FileTimeToSystemTime(pFileTime, &stUtc);
        return Iirf_SystemTimeUtcToLocalTimeString(&stUtc);
    }
}


void Iirf_TrimCrlf(char * s, size_t sz)
{
    size_t len = strlen(s);
    if (len <= sz) {  // sanity
        size_t i;
        for (i= len-1; i >=0 && s[i]!='/0' && s[i]<' '; i--) {
            s[i]='\0';
        }
    }
}

void Iirf_GenErrorMessage(errno_t e, char * s, DWORD sz)
{
    int rv = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,0,e,0,s,sz,NULL);
    if (rv==0) {
        // an error occurred while trying to format the error message
        int e2 = GetLastError();
        sprintf_s(s, sz, "e2=%d", e2);
    }
    else
        Iirf_TrimCrlf(s, sz);
}


