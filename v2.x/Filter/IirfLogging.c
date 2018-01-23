#define DEBUGTRACE  0

/*

  IirfLogging.c

  Ionic's Isapi Rewrite Filter [IIRF]

  ISAPI Filter that does  URL-rewriting.
  Inspired by Apache's mod_rewrite .
  Implemented in C, does not use MFC.

  Copyright (c) Dino Chiesa, 2005-2010.  All rights reserved.

  ==================================================================

  Licensed under the MS Public License.
  http://opensource.org/licenses/ms-pl.html

  See the attached License.txt file, or see the Rewriter.c module for
  the details of the license for IIRF.

  Last saved: <2011-September-11 18:12:43>

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <share.h>     // for _SH_DENY?? menmonics

#include <WTypes.h>    // for DWORD, etc

#include "Iirf.h"

// globals
LogFileEntry *gLogFileList = NULL;

// extern decls
extern void Iirf_GenErrorMessage(errno_t e, char * s, DWORD sz);                                         // Utils.c
extern void Iirf_EmitEventLogEventX( WORD infoType, DWORD dwEventId, LPTSTR msg2, const char * format, ... );  // Utils.c
extern CRITICAL_SECTION gcsFilterConfig;
extern CRITICAL_SECTION gcsLogFileList;
extern IirfServerConfig * gFilterConfig;
extern LogFileEntry * gLogFileList;
extern char * gIirfVersion;
extern char * gIirfBuildSig;  // timestamp generated at compile-time, inserted into a separate module

extern void InsertIirfStatusMsg(IirfVdirConfig *tc, char * msg, int flavor);                            // IirfConfig.c


// forward decls
void LogMessage( IirfVdirConfig * cfg, int MsgLevel, const char * format, ... );



/*

  IIRF is an ISAPI, and therefore gets loaded by IIS into potentially
  multiple independent w3wp.exe processes. Also the w3wp.exe is
  potentially multi-threaded. So there is some degree of concurrency
  that must be managed. In the case of handling HTTP requests, this
  concurrency is easily handled by relying on the request context, which
  is provided in HTTP_FILTER_CONTEXT that gets passed to the various
  ISAPI events: OnUrlMap, OnAuthComplete, etc.

  There's a twist - IIRF allows the user to modify the IIRF.ini at any
  time, and it reloads the configuration from the ini, whenever
  appropriate. It does this by checking the timestamp on the ini file
  for each request, and reloading inline when appropriate. It's possible
  for an HTTP request to trigger an ini-reload, while another HTTP
  request is still using the prior "epoch" of the ini file.  So, the
  config for a vdir is refcounted, and is reaped only after a timeout
  expires AND the refcount is at zero.

  One of the things configured in the ini file is the IIRF logfile. But
  we want IIRF to maintain only a single open file pointer to each
  logfile. Opening the same filesystem path multiple times would result
  in a confused logfile, with corrupted log messages, and possibly file
  errors.  To avoid this, IIRF keeps a separate list, essentially an
  associative array, that maps logfile names to open file
  pointers. Commonly an ini file update will modify one or more rules,
  but not change the logfile; this means the open file pointers for
  logfiles normally live longer than an instance of a vdir configuration
  as read from an ini file.

  This module manages the logfile output, and also the opening / closing
  of each IIRF logfile.

  In particular, IIRF attempts to open an iirf logfile only once. If it
  succeeds, the file pointer is stored in the refcounted vdir config
  structure and re-used. If the fopen fails, then IIRF emits an event
  into the Windows Event Log, and never tries to open that logfile
  again.

*/



#if DEBUGTRACE
static FILE * gLog = NULL;
static char * DebugLogFile = "c:\\inetpub\\iirfLogs\\IIRF-Debug.log";

void VTRACE(const char * format, va_list argp)
{
    char * MessageBuffer;
    int len;
    if (gLog == NULL) {
        // if testing (like TestDriver.exe) then output is stdout.  Else, use a file.
        gLog= (gFilterConfig == NULL || !gFilterConfig->Testing)
            ? _fsopen(DebugLogFile,"a+", _SH_DENYNO )
            : stdout ;
        fprintf(gLog,"\n-------------------------------------------------------\n");
    }
    len = _vscprintf( format, argp ) + 1; // _vscprintf doesn't count terminating '\0'
    MessageBuffer= malloc( len * sizeof(char) );
    vsprintf_s( MessageBuffer, len, format, argp );
    fprintf(gLog,"%s\n",MessageBuffer);
    free( MessageBuffer );

    fflush(gLog);
}


void TRACE( const char * format, ... )
{
    va_list argp;
    va_start( argp, format );
    VTRACE(format, argp);
    va_end(argp);
}

void CacheLogMessage( int level, const char * format, ... )
{
    va_list argp;
    va_start( argp, format );
    VTRACE(format, argp);
    va_end(argp);
}


#else


/*
 * CacheLogMessage
 *
 * Caches the given message until such time as a logfile is available.
 * Generally this is used for log messages at filter startup, but
 * before any site configuration is loaded. The messages are cached
 * until they are emitted into the logfile of the first site.
 *
 */
void CacheLogMessage( int level, const char * format, ... )
{
    va_list args;
    CachedLogMessage * Msg = (CachedLogMessage *) malloc(sizeof(CachedLogMessage));
    int len;
    va_start( args, format );
    len = _vscprintf( format, args ) + 1; // _vscprintf doesn't count terminating '\0'
    Msg->Data= malloc( len * sizeof(char) );
    vsprintf_s( Msg->Data, len, format, args );
    Msg->Next = NULL;
    Msg->Level = level;

    EnterCriticalSection(&gcsFilterConfig);

    // cache it:
    if (gFilterConfig->MsgCache==NULL)
        gFilterConfig->MsgCache= Msg;
    else {
        CachedLogMessage * c= gFilterConfig->MsgCache;
        while (c->Next != NULL) c= c->Next;
        c->Next = Msg;
    }

    LeaveCriticalSection(&gcsFilterConfig);
}

void TRACE(const char * format, ...)
{
}


#endif




void EmitCachedMessages( IirfVdirConfig * cfg, int allOneLevel)
{
    if (gFilterConfig->MsgCache)
    {
        int level;
        CachedLogMessage * currentMsg;
        CachedLogMessage * previousMsg;
        EnterCriticalSection(&gcsFilterConfig);
        currentMsg = gFilterConfig->MsgCache;
        gFilterConfig->MsgCache= NULL; // prevent infinite recursion
        while (currentMsg != NULL) {
            level = allOneLevel ? 1 : currentMsg->Level;
            LogMessage(cfg, level, "Cached: %s", currentMsg->Data);
            previousMsg = currentMsg;
            currentMsg= currentMsg->Next;
            // clean up as we go
            free(previousMsg->Data);
            free(previousMsg);
        }
        LeaveCriticalSection(&gcsFilterConfig);
    }
}



static const char * logFormat = "%s - %5d - %s\n";
static const char * logFormat_NoNewline = "%s - %5d - %s";


void LogMessage( IirfVdirConfig * cfg, int MsgLevel, const char * format, ... )
{

#if DEBUGTRACE
    time_t t;
    char TimeBuffer[26] ;
    va_list args;
    int len;
    char * MessageBuffer;

    if (gLog == NULL) {
        gLog= _fsopen(DebugLogFile, "w", _SH_DENYWR );
    }

    time(&t);
    ctime_s(TimeBuffer,26,&t);
    // 0123456789012345678901234 5
    // Wed Jan 02 02:03:55 1980\n\0
    TimeBuffer[24]=0; // null out final newline

    va_start( args, format );
    len = _vscprintf( format, args ) + 1; // _vscprintf doesn't count terminating '\0'
    MessageBuffer = malloc( len * sizeof(char) );
    vsprintf_s( MessageBuffer, len, format, args );
    fprintf(gLog,"%s - %s\n", TimeBuffer,MessageBuffer);
    free( MessageBuffer );

    fflush(gLog);

#else

    if (cfg==NULL) return;

    if (cfg->LogLevel >= MsgLevel) {

        if (cfg->pLogFile==NULL) return; // sanity check

        if (cfg->pLogFile->LogFile!=NULL) {
            // the original logfile has been successfully opened
            const char * format1;
            time_t t;
            char TimeBuffer[26] ;
            va_list args;
            int len;
            char * MessageBuffer;
            int r;

            if (MsgLevel > 0 && gFilterConfig->MsgCache) EmitCachedMessages(cfg, 0);

            time(&t);
            ctime_s(TimeBuffer,26,&t);
            // 0123456789012345678901234 5
            // Wed Jan 02 02:03:55 1980\n\0
            TimeBuffer[19]=0; // terminate before year and newline
            va_start( args, format );
            len = _vscprintf( format, args ) + 1; // _vscprintf doesn't count terminating '\0'
            MessageBuffer = malloc( len * sizeof(char) );
            r= vsprintf_s( MessageBuffer, len, format, args );
            format1 = (MessageBuffer[len-2]=='\n')?logFormat_NoNewline : logFormat;
            fprintf(cfg->pLogFile->LogFile, format1, TimeBuffer, GetCurrentThreadId(), (r!=-1)?MessageBuffer:format);
            free( MessageBuffer );
            fflush(cfg->pLogFile->LogFile);
        }
    }

#endif

}



void ReleaseLogFile(LogFileEntry *e)
{
    CRITICAL_SECTION *pCS;
    boolean destroyed = FALSE;
    if (e == NULL) return;

    EnterCriticalSection(e->pCS);
    pCS = e->pCS;
    e->RefCount--;

    if (e->RefCount <= 0) {
        destroyed = TRUE;
        if (e->LogFileName) free(e->LogFileName);
        if (e->LogFile) fclose(e->LogFile);

        // handle global logfile list
        EnterCriticalSection(&gcsLogFileList);
        if (gLogFileList == e)
            gLogFileList = NULL;
        else {
            // remove that element from the linked list
            LogFileEntry *current = gLogFileList;
            while (current && current->Next != e) current = current->Next;
            if (current && current->Next)
                current->Next = e->Next;
        }
        LeaveCriticalSection(&gcsLogFileList);

        free(e);
    }
    LeaveCriticalSection(pCS);
    if (destroyed) {
        DeleteCriticalSection(pCS);
        free(pCS);
    }
    return;
}







// http://www.codeplex.com/IIRF/WorkItem/View.aspx?WorkItemId=17002
void IirfInvalidParameterHandler(
    const wchar_t* wszExpression,
    const wchar_t* wszFunction,
    const wchar_t* wszFile,
    unsigned int line,
    uintptr_t pReserved)
{
    // We had a bad pointer, or something.  Log an event in the event log.
    Iirf_EmitEventLogEventX(EVENTLOG_WARNING_TYPE, IIRF_EVENT_INVALID_PARAM, NULL,
                       "Invalid Parameter: expression(%S) func(%S) file(%S) line(%d)",
                       wszExpression, wszFunction, wszFile, line);
}





LogFileEntry * NewLogFile(IirfVdirConfig * cfg, char *LogFileName)
{
    LogFileEntry * a = malloc(sizeof(LogFileEntry));
    char *actualLogfileName = (gFilterConfig->Testing) ? "CON":LogFileName;
    int n = Iirf_ConvertSizeTo32bits(strlen(LogFileName)+1);
    TRACE("NewLogFile: logfilename = '%s'", LogFileName);

    a->RefCount = 1;
    a->LogFileName = (char *) malloc(n * sizeof(char));
    strcpy_s(a->LogFileName, n, LogFileName);

    a->pCS= malloc(sizeof(CRITICAL_SECTION));
    InitializeCriticalSection(a->pCS);

    a->LogFile = (gFilterConfig->Testing) ? stdout :
        //_fsopen(actualLogfileName,"w", _SH_DENYNO )
        _fsopen(actualLogfileName,"a", _SH_DENYWR );

    if (a->LogFile==NULL) {
        TRACE("NewLogFile: Could not open log file '%s' (error: %d), trying with 'w' flag.", actualLogfileName, GetLastError());
        a->LogFile= _fsopen(actualLogfileName, "w", _SH_DENYNO );
        if (a->LogFile==NULL) {
            TCHAR eMsg[256];
            int e = GetLastError();
            const char * eventMsgFormat = "IIRF: Could not open or create log file '%s' (error: %d, %s)";
            int len;
            char *msg;
            Iirf_GenErrorMessage(e, eMsg, 256);
            TRACE("NewLogFile: 2nd try, Could not open or create log file '%s' (error: %d, %s)",
                  actualLogfileName, e, eMsg);
            Iirf_EmitEventLogEventX(EVENTLOG_WARNING_TYPE, IIRF_EVENT_BAD_LOGFILE, NULL,
                                    eventMsgFormat, actualLogfileName, e, eMsg);

            // put into the cache for the /iirfStatus report
            len = _scprintf( eventMsgFormat, actualLogfileName, e, eMsg) + 1;
            msg = malloc( len * sizeof(char) );
            sprintf_s(msg, len, eventMsgFormat, actualLogfileName, e, eMsg);
            InsertIirfStatusMsg(cfg, msg, 2);
            // free(msg); NO - will be freed later upon release of config
        }
    }

    TRACE("NewLogFile: LogFile = 0x%08X", a->LogFile);
    a->Next = NULL;

    return a;
}





LogFileEntry * GetLogFile(IirfVdirConfig * cfg)
{
    LogFileEntry *current, *previous = NULL;
    char *logFileName = cfg->LogFileName;

    TRACE("GetLogFile");

    EnterCriticalSection(&gcsLogFileList);
    current = gLogFileList;
    // see if we can find a match in the stack:
    TRACE("GetLogFile: root= 0x%08X", current);
    while (current != NULL) {
        TRACE("GetLogFile: compare: '%s'  '%s'", current->LogFileName, logFileName);
        if (strcmp(current->LogFileName, logFileName)==0) {
            // increment the refcount, then return the pointer
            current->RefCount++;
            LeaveCriticalSection(&gcsLogFileList);
            // insert this entry into the given site config:
            EnterCriticalSection(cfg->pCS);
            cfg->pLogFile = current;
            LeaveCriticalSection(cfg->pCS);
            return current;
        }
        previous = current;
        current = current->Next;
        TRACE("GetLogFile: next= 0x%08X", current);
    }

    // Arriving here means there is no open file pointer available for
    // the given logFileName.
    // So we create one, and insert it into the list.

    current = NewLogFile(cfg, logFileName);
    TRACE("GetLogFile: new= 0x%08X", current);
    if (gLogFileList == NULL) {
        gLogFileList = current;
    }
    else {
        // append to the linked list
        previous->Next = current;
    }

    LeaveCriticalSection(&gcsLogFileList);

    // insert this entry into the given site config:
    EnterCriticalSection(cfg->pCS);
    cfg->pLogFile = current;
    LeaveCriticalSection(cfg->pCS);

    // emit some introductory information when first opening a log file...
    LogMessage(cfg, 0, "-------------------------------------------------------");
    LogMessage(cfg, 0, "%s", gIirfVersion);
    LogMessage(cfg, 0, "IIRF was built on: %s", gIirfBuildSig);

    EmitCachedMessages(cfg, 0);

    LogMessage(cfg, 1, "GetLogFile: app:'%s'  new log:'%s'", cfg->ApplMdPath, cfg->LogFileName);

    return current;
}

