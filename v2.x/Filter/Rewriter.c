//#define ARTIFICIAL_FAIL    1

/*
  Rewriter.c

  part of Ionic's Isapi Rewrite Filter [IIRF]

  IIRF is an ISAPI Filter that does URL-rewriting.
  Inspired by Apache's mod_rewrite .
  Implemented in C, does not use MFC.

  Copyright (c) Dino Chiesa, 2005-2011.
  All rights reserved.

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
  dependencies:

  PCRE - the Perl-compatible Regular Expression library, from Hazel.
         This is for pattern matching.

*/


/* Design notes: */

/* The gVdirConfigList is a singly-linked list of vdir-specific configuration data
 * structures.  The IIS administrative model has these concepts: server (machine), site
 * (port), vdir/app (ApplMdPath).  In IIRF, each web app or vdir has a distinct
 * configuration, read from its own IIRF.ini file. This data included in this
 * configuration block includes the rules (Rewrite, redirect, proxy) with all of their
 * conditions, the maps that are used in those rules, and the other related metadata.

 * When a request arrives at the
 * filter on a particular thread, the thread scans the global gVdirConfigList to
 * find a config that maps to the given APPL_MD_PATH.  If one is found, the thread
 * copies the pointer to that configuration information into the request context.
 * At this point, the vdir configuration is available within the pFilterContext of
 * HTTP_FILTER_CONTEXT.
 *
 * If on the other hand, there is no config found that maps to the given APPL_MD_PATH,
 * then the thread reads in the config information from the iirf.ini file, and inserts
 * the newly-read config information into the gVdirConfigList.  (If the ini file does
 * not exist or cannot be read, then that request gets a "null" or default
 * configuration). The insertion into the list is protected by a CRITICALSECTION.
 *
 * With this approach, there are M threads running within the filter,
 * mapping in some way to N vdir configuration structures.
 *
 * There is an additional wrinkle: the IIRF operator may at any time change an IIRF
 * setting for any vdir or web app, by modifying the IIRF.ini file, or any file it
 * includes (map files, included ini files).  To allow for these updates, IIRF, for
 * each incoming request, checks for updated configuration settings. Here's how
 * that is done:
 *
 * According to the ISAPI model, IIS invokes HttpFilterProc() multiple times for each
 * request. When HttpFilterProc is invoked for the first time for a given request,
 * IIRF initializes the vdir configuration data that applies to that particular
 * request, via a call to InitCustomFilterContext(), and stores a pointer to the
 * config data into the custom context pointer made available by the ISAPI
 * model. InitCustomFilterContext calls GetVdirConfigFromServerVars(), which uses the
 * APPL_MD_PATH to find an existing copy of the configuration data structure for the
 * given vdir, in the linked list called gVdirConfigList.  If none exists, then the
 * configuration data is read in from the appropriate ini file, and is placed into
 * the linked list. If there is a config data block for the given vdir, the date of
 * the data block is checked against the date of the ini files backing the
 * configuration, and if any ini files have been updated, then the configuration is
 * read in again, and placed into the linked list.
 *
 * On subsequent invocations of HttpFilterProc for the same request, IIRF retrieves
 * that configuration data block directly from the filter context pointer
 * (pFilterContext) that IIS automatically associates to the request.
 *

 * When reading in new configuration data, it is not ok to discard the old
 * vdir-configuration structure immediately, because some of the M threads running in
 * the filter may be actively using the "stale" configuration data structures, read
 * from the prior versions of the now-updated configuration files. To manage this
 * situation, each vdir config structure in the gVdirConfigList is
 * reference-counted. When a vdir config block is first mapped to a request, IIRF
 * increments the reference count. When a request completes, IIRF calls
 * ReleaseVdirConfig() which decrements the reference count, and checks to see if the
 * data block should be freed. If the refcount is zero AND the data block is marked
 * "Expired", IIRF frees it and removes it from the linked list. How does it get to be
 * marked Expired?  When an ini file is updated and new data is read in, IIRF calls
 * ExpireVdirConfig() to mark the old data block as expired.  As with
 * ReleaseVdirConfig(), if the reference count is zero, then that data block is also
 * freed and removed from the global linked list.  That takes care of the management of
 * concurrent access to changing vdir configuration data.
 *
 * One last twist - each vdir config allows the operator to specify a log file.
 * There are M threads writing to N log files, and some of the threads are writing to
 * the same log file. To avoid write stomping, it is imperative that multiple threads
 * writing to a common logfile all share the same file pointer. This might seem easy
 * enough: use the vdir config structure to store the log file pointer. Then, any of
 * the M threads across N vdir configuration structures will have the right file
 * pointer. Not so fast.
 *
 *
 * The challenge is when the ini file is updated - the change to the ini file might
 * change the location of the logfile, or... it might not.  When the logfile is
 * unchanged across a change in the ini file, we want the file pointer for the logfile
 * to remain open - so that it is used for the doomed vdir configuration structures
 * (stale but still in use), as well as the current vdir config structure.  And, Yes,
 * there can be multiple expired configurations for a given vdir.  The constraint,
 * simply stated, is this: the IIRF DLL must maintain only a single logfile pointer for
 * any given logfile.
 *
 * As a result, there must be a dictionary of logfile pointers, maintained
 * separately from the list of ref-counted vdir config structures. We need AT MOST
 * N logfile pointers, where N is the number of vdirs, whereas there will be at most
 * M vdir config structures, where M is the number of IIS threads. At MOST N,
 * because in fact some vdirs may log to the same logfile. Although this may result
 * in confusing logfiles with interleaved messages, it is legal and supported.
 *
 * The vdir configuration list can have at most N *current* vdir configs, but it can
 * also potentially have N+P *total* vdir configs, P of them expired, where N+P =
 * M. Those P expired vdir configs potentially use the same logfiles as other
 * non-expired vdir configs. If they use the same logfiles, they must share logfile
 * pointers.
 *
 * We use the canonicalized logfilename, stored in the vdir config, as a reference
 * into the dictionary of logfile pointers, gLogFileList. The logfile pointers are
 * also refcounted.  Each logfile pointer is also protected by a mutex, so only a
 * single thread can write to the logfile at any one moment.
 *
 * So there are two similar dictionaries - one is the gVdirConfigList, which is
 * looked up by the APPL_MD_PATH of the app/vdir.  The other is the gLogFileList,
 * which is looked up by logfilename.  Each URL request has the server variable
 * APPL_MD_PATH set to the IIS Application path (a metabase datum).  This then
 * identities a unique Vdir Config entry (IirfVdirConfig) for the request.  The
 * VdirConfig entry has a logfilename within it, which is used to lookup into the
 * gLogFileList for a logfile pointer unique for that file. Furshtay?
 *
 ******************************************************************************/

#ifdef _DEBUG
char *buildFlavor = "DEBUG";
#ifdef _WIN64
#pragma message("  DEBUG x64 build")
char *cpuFlavor = "x64";
#else
#pragma message("  DEBUG x86 build")
char *cpuFlavor = "x86";
#endif
#else
char *buildFlavor = "RELEASE";
#ifdef _WIN64
#pragma message("  RELEASE x64 build")
char *cpuFlavor = "x64";
#else
#pragma message("  RELEASE x86 build")
char *cpuFlavor = "x86";
#endif
#endif




#define IIRF_FILTER_NAME "Ionic ISAPI Rewriting Filter (IIRF)"


#define _CRT_RAND_S
#include <stdlib.h>   // for rand_s()
#include <stdio.h>
#include <tchar.h>
#include <math.h>     // for log10()
#include <time.h>
#include <crtdbg.h>   // for _CRT_ASSERT

#include <WTypes.h>   // for DWORD, etc
#include <HttpFilt.h> // HTTP_FILTER_CONTEXT, etc
#include <HttpExt.h>  // EXTENSION_CONTROL_BLOCK, HSE_VERSION_INFO

#include <pcre.h>

#include "IIRF.h"


// statics and globals
volatile BOOL     gFilterInitialized = FALSE;
volatile BOOL     gAlreadyCleanedUp = FALSE;
CRITICAL_SECTION  gcsFilterConfig;
CRITICAL_SECTION  gcsVdirConfig;
CRITICAL_SECTION  gcsLogFileList;

char *gIirfVersion = NULL;
char *gIirfShortVersion = NULL;
char *gIirfBuildSig = __DATE__ " " __TIME__ ;
IirfServerConfig *gFilterConfig = NULL;

// externs
// externs: IirfLogging.c
extern void LogMessage( IirfVdirConfig * cfg, int MsgLevel, const char * format, ... );
extern void CacheLogMessage( int level, const char * format, ... );
extern void TRACE(const char * format, ...);
extern void IirfInvalidParameterHandler( const wchar_t* wszExpression,
                                         const wchar_t* wszFunction,
                                         const wchar_t* wszFile,
                                         unsigned int line,
                                         uintptr_t pReserved);

// externs: IirfConfig.c
extern IirfVdirConfig * GetVdirConfigFromServerVars(HTTP_FILTER_CONTEXT * pfc);
extern IirfVdirConfig * GetVdirConfigFromFilterContext(HTTP_FILTER_CONTEXT * pfc);
extern char * Iirf_FileTimeToLocalTimeString(FILETIME * pFiletime);
extern char * Iirf_SystemTimeUtcToLocalTimeString(SYSTEMTIME * pSysTime);
extern IirfServerConfig * Iirf_NewServerConfig();
extern void Iirf_ReadServerConfig(IirfServerConfig * thisConfig);
extern int Iirf_FindMapItemByKey( char ** key, TextMapItem *item );

// externs: UrlDecoder.c
extern char * UrlDecode(char * encoded);
extern char * UrlEncode(char * decoded);
extern void InitializeUrlDecoder();

// extern: Proxy.c
extern DWORD IirfProxy_TryRelayEmptyBodyRequest(HTTP_FILTER_CONTEXT * pfc,
                        LPCTSTR fqUrl,
                        LPCTSTR origHost,
                        int *pContentChunks,
                        int *pContentTotalBytes);

// externs: Extension.c
extern char * Iirf_Rfc1123_DateTimeNow();

// externs: Utils.c
extern char * Iirf_AllocAndSprintf( HTTP_FILTER_CONTEXT * pfc, const char * format, ... );
extern char * Iirf_AllocAndConcatenate(char *s1, char *s2);
extern char * Iirf_IsapiStrdup( HTTP_FILTER_CONTEXT * pfc, const char * source);
extern void Iirf_GenErrorMessage(errno_t e, char * s, DWORD sz);
extern BOOL Iirf_FileExists(const TCHAR *fileName);

// externs: ExceptionHandler.cpp
extern int ExceptionFilter(EXCEPTION_POINTERS *pExp, IirfVdirConfig * cfg);


// forward decls
void StashHeader(HTTP_FILTER_CONTEXT * pfc, char * variableName, char * value );
char * GetStashedHeader_AutoFree(HTTP_FILTER_CONTEXT * pfc, char * variableName );
IirfVdirConfig * GetVdirConfig(char * ApplMdPath, char * ApplPhysicalPath);
IirfVdirConfig * ReadVdirConfig(char * ConfigFile, char * ApplMdPath, IirfVdirConfig * oldCfg) ;
void ReleaseVdirConfig (IirfVdirConfig * deadConfig) ;
int Iirf_EvaluateRules(HTTP_FILTER_CONTEXT * pfc, char * subject, int depth, RewriteRule ** matchedRule, char **resultUri);
char * GetServerVariable(PHTTP_FILTER_CONTEXT pfc, char * variableName );
char * GetServerVariable_AutoFree( PHTTP_FILTER_CONTEXT pfc, char * variableName );
char * GetHeader_AutoFree(PHTTP_FILTER_CONTEXT pfc, char * variableName );
char * GetHeader(PHTTP_FILTER_CONTEXT pfc, char * variableName );

char *gIirfStartupTime = NULL;

char *gStyleMarkup= "  <style>\n"
    "    p,tr,td,body,a {font-family: Verdana, Arial, Helvetica; font-size: 9pt;}\n"
    "    h1 {color: #4169E1;}"
    "    h2 {color: #1E90FF;}"
    "    table {border: 1 solid gray; padding: 0 0 0 0;}\n"
    "    tr td {color: Navy; }\n"
    "    tr th {color: #00008B; background: #E6E6FA;}\n"
    "    td {padding: 0em 1em 0em 1em;}\n"
    "    .sm {font-size: 8pt;}\n"
    "    .elist {margin: 1em 0em 0em 0em; color: #2F4F4F; border: 1 solid #808080; padding: 10px 1em 10px 1em; background: #F8F8FF;}\n"
    "   </style>\n";


typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR DataBuffer[1];
        } GenericReparseBuffer;
    } ;
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;



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
    CacheLogMessage(1, "GetFilterVersion");

    while (!gFilterInitialized)
        Sleep(120); // wait til config is loaded

    pVer->dwFilterVersion = HTTP_FILTER_REVISION;

    // filter priority
    pVer->dwFlags |=   gFilterConfig->FilterPriority;

    // security
    pVer->dwFlags |=  SF_NOTIFY_SECURE_PORT | SF_NOTIFY_NONSECURE_PORT ;

    // notification to allow pre-processing of headers
    //pVer->dwFlags |= SF_NOTIFY_PREPROC_HEADERS;

    // we use AUTH_COMPLETE because more server variables are parsed by then.
    pVer->dwFlags |= SF_NOTIFY_AUTH_COMPLETE;

    // this is to calculate the REQUEST_FILENAME.
    pVer->dwFlags |= SF_NOTIFY_URL_MAP;

    // for freeing resources.
    pVer->dwFlags |= SF_NOTIFY_END_OF_REQUEST;

    // notification to allow tweaking of logs (unmangling of URLs).

    // Here, we decide whether to register for LOG events based on the need.
    // The reason is, SF_NOTIFY_LOG is cache hostile - it will disable the
    // IIS6/7 kernel mode cache, which is bad. So, we register for this event
    // only when the server-side config file specifies it.
    //

    // If the admin wants to log the unmodified (un-mangled) URLs in the IIS
    // log file, then he needs to specify "NotifyLog ON" in the server-wide
    // config file, and also, in the vdir-specific config file, needs to apply
    // a [U] flag to any rewrite rule that fires for a URL.
    //

    // If the admin does not want to log the unmodified URLs, then don't use a
    // NotifyLog setting in the server-wide config file.  In this case, any
    // vdir-specific rules with the [U] flag will not work.  We'll log a
    // message when we read such a configuration.

    if (gFilterConfig->WantNotifyLog)
        pVer->dwFlags |= SF_NOTIFY_LOG ;

    strncpy_s(pVer->lpszFilterDesc, sizeof(pVer->lpszFilterDesc), gIirfVersion, _TRUNCATE );
    return TRUE;
}




/* InitCustomFilterContext
 *
 * Purpose:
 *
 *     Set up the custom filter context pointer, initialize the fields.
 *     This is done once per request...
 *     The context holds:
 *         - the physical path, maybe necessary if we are doing
 *           file-existence checking.
 *         - the original URI stem (sometimes), used when the [U] flag
 *           is applied, to log unmangled URIs.
 *         - the vdir config used for the request throughout its life.
 *
 */
boolean InitCustomFilterContext(HTTP_FILTER_CONTEXT * pfc)
{
    IirfRequestContext *ctx;

    TRACE("InitCustomFilterContext");

    if (pfc->pFilterContext!=NULL) {
        TRACE("InitCustomFilterContext: Already initialized (ctx=0x%08X).", pfc->pFilterContext);
        return FALSE;  // already initialized
    }

    ctx = (IirfRequestContext *) pfc->AllocMem(pfc, sizeof(IirfRequestContext), 0);
    if ( ctx == NULL ) {
        SetLastError( ERROR_NOT_ENOUGH_MEMORY );
        return FALSE;
    }
    pfc->pFilterContext    = ctx;

    ctx->Magic             = IIRF_CONTEXT_MAGIC_NUMBER;
    ctx->OriginalUriStem   = NULL;
    ctx->QueryString       = NULL;
    ctx->RequestUri        = NULL;
    ctx->RequestMethod     = NULL;
    ctx->PhysicalPath      = NULL;
    ctx->RecordOriginalUri = FALSE;
    ctx->AuthCompleteInfo  = NULL;
    ctx->InterimUrl        = NULL;
    ctx->InterimMethod     = NULL;
    ctx->VdirConfig        = GetVdirConfigFromServerVars(pfc);

    return TRUE;
}





/* SetRequestInfoInCustomFilterContext
 *
 * Purpose:
 *
 *     Set the original URL, and the request method, into the custom filter
 *     context buffer.  This info is then available later, for any purpose.
 *     In particular, it can be used in the SF_NOTIFY_LOG
 *     event for logging the "unmangled" URL, or in GetServerVariable to
 *     get the special value "REQUEST_URI".   In the former case, the URI
 *     query string and method are all logged independently in the IIS Log.
 *
 * Arguments:
 *
 *     pfc - HTTP_FILTER_CONTEXT - this is the thing that holds the custom
 *           context pointer (pfc->pFilterContext).  The custom pointer should
 *           have been previously allocated. (in OnUrlMap).
 *
 *     uriStem - the original URL stem, up to but not including the ? (if any)
 *
 *     queryString - the original query string,  everything following the ? (if any)
 *
 *     requestMethod - eg, GET, POST, HEAD, OPTIONS, etc
 *
 * Returns:
 *
 *     (char *)
 *         the original URI, including path and query string if any.
 *         This ptr is AllocMem'd, will be free'd automatically at request end.
 *
 */
char * SetRequestInfoInCustomFilterContext(HTTP_FILTER_CONTEXT * pfc,
                                           char * uriStem,
                                           char * queryString,
                                           char * requestMethod )
{
    if (pfc->pFilterContext==NULL) return NULL;
    else {
        IirfRequestContext *ctx = (IirfRequestContext *) pfc->pFilterContext;

        if (ctx->Magic == IIRF_CONTEXT_MAGIC_NUMBER) {
            size_t dwSize= strlen(uriStem) + 1 + strlen(queryString) + 1;
            int sz32 = Iirf_ConvertSizeTo32bits(dwSize);
            ctx->OriginalUriStem= uriStem;
            ctx->QueryString= queryString;
            ctx->RequestMethod= requestMethod;

            ctx->RequestUri= (char *) pfc->AllocMem(pfc, sz32, 0);
            strcpy_s(ctx->RequestUri, sz32, uriStem);
            if ((queryString!=NULL) && (strlen(queryString) > 0)) {
                strcat_s(ctx->RequestUri, sz32, "?");
                strcat_s(ctx->RequestUri, sz32, queryString);
            }
            return ctx->RequestUri;
        }

        LogMessage(ctx->VdirConfig, 2, "Bad Magic number for IIRF Filter Context.");
        return NULL;
    }
}


boolean SetRecordOriginalUri(HTTP_FILTER_CONTEXT * pfc)
{
    IirfRequestContext *ctx = (IirfRequestContext *) pfc->pFilterContext;
    if (ctx->Magic == IIRF_CONTEXT_MAGIC_NUMBER) {
        ctx->RecordOriginalUri = TRUE;
        return TRUE;
    }
    return FALSE;
}

boolean GetRecordOriginalUri(HTTP_FILTER_CONTEXT * pfc)
{
    IirfRequestContext *ctx = (IirfRequestContext *) pfc->pFilterContext;
    if (ctx->Magic == IIRF_CONTEXT_MAGIC_NUMBER) {
        return ctx->RecordOriginalUri;
    }
    return FALSE;
}



char * FormatStatusMsgs(IirfVdirConfig * cfg)
{
    char * html;
    int n = 0;

    static const char * prefix = "<div class='elist'><pre>Messages:\n";
    static const char * suffix = "</pre></div>";
    size_t bsize = 0;
    ArchivedStatusMessage * node;
    if (cfg->statusMsgs == NULL) return NULL;

    // first, count the size
    node = cfg->statusMsgs;
    do {
        n++;
        bsize += strlen(node->Text);
        node = node->Next;
    } while (node != NULL);

    // Add space for the prefix, suffix, and newlines.
    bsize += strlen(prefix) + strlen(suffix) + (4 * n) + 2;
    html = malloc(bsize * sizeof(char));
    strcpy_s(html, bsize, prefix);

    // strcat each msg
    node = cfg->statusMsgs;
    do {
        strcat_s(html, bsize, node->Text);
        strcat_s(html, bsize, "\n");
        node = node->Next;
    } while (node != NULL);

    strcat_s(html, bsize, suffix);
    return html; // caller must free
}


char * FormatVdirStatus(IirfVdirConfig * cfg)
{
#define IIRF_TSTR_LEN  128
    BOOL logFileExists = (cfg->LogFileName && Iirf_FileExists(cfg->LogFileName)),
        iniFileExists = (cfg->IniChain->Name && Iirf_FileExists(cfg->IniChain->Name));

    char *htmlContent,
        *eStyle        = " style='color:Red;background:Pink;'",
        *iniFileStyle  = iniFileExists ? "" : eStyle,
        *lastWrite     = Iirf_FileTimeToLocalTimeString(&(cfg->IniChain->LastWrite)),
        *lastReadHdr   = iniFileExists ? "Last Read" : "Last Read Attempt",
        *lastReadTime  = Iirf_SystemTimeUtcToLocalTimeString(&(cfg->ConfigRead)),
        *nErrors       = (char *) malloc(IIRF_TSTR_LEN),
        *nWarnings     = (char *) malloc(IIRF_TSTR_LEN),
        *logFileStyle  = logFileExists ? "" : eStyle,
        *logFileMsg    = cfg->LogFileName ? (logFileExists ? "" : " (does not exist)") : "",
        *errorStyle    = (cfg->nErrors > 0) ? eStyle : "",
        *warningStyle  = (cfg->nWarnings > 0)? eStyle : "",
        *allStatusMsgs = FormatStatusMsgs(cfg);

    static const char * vdirStatusFormat =
        "<h2>IIRF Vdir Status</h2>"
        "<table border='1px'>"
        "<tr><th>APPL_MD_PATH</th><td>%s</td></tr>\n"
        "<tr><th%s>Root Vdir Ini File</th><td>%s</td></tr>\n"

        "<tr><th%s>Ini file timestamp</th><td>%s</td></tr>\n"
        "<tr><th>%s</th><td>%s</td></tr>\n"
        "<tr><th>#Ini Modules</th><td>%d</td></tr>\n"
        "<tr><th>#Lines</th><td>%d</td></tr>\n"
        "<tr><th>#Rules</th><td>%d</td></tr>\n"
        "<tr><th%s>#Warnings</th><td>%s</td></tr>\n"
        "<tr><th%s>#Errors</th><td>%s</td></tr>\n"

        "<tr><th%s>Log file %s</th><td>%s</td></tr>\n"
        "<tr><th>Log level</th><td>%d</td></tr>\n"
        "<tr><th>Rewrite Engine</th><td>%s</td></tr>\n"
        "<tr><th>Rewrite Base</th><td>'%s'</td></tr>\n"
        "<tr><th>Remote Status Inquiry</th><td>%s</td></tr>\n"

        "<tr><th>Cond substring flag</th><td>%c</td></tr>\n"
        "<tr><th>Case conversion flag</th><td>%c</td></tr>\n"

        "<tr><th>URL Decoding</th><td>%s</td></tr>\n"
        "<tr><th>Iteration Limit</th><td>%d</td></tr>\n"
        "<tr><th>Proxy Timeouts (sec.)</th><td> Resolve=%d Connect=%d Send=%d Receive=%d</td></tr>\n"
        "<tr><th>#Requests Processed</th><td>%d</td></tr>\n"
        "</table>\n%s";

    sprintf_s(nErrors, IIRF_TSTR_LEN, (cfg->nErrors > 0)?"<span style='color:Red; font-weight: Bold;'>%d</span>&nbsp;<span class='sm'>(see messages below)</span>" : "%d",
              cfg->nErrors);

    sprintf_s(nWarnings, IIRF_TSTR_LEN, (cfg->nWarnings > 0)?"<span style='color:Red; font-weight: Bold;'>%d</span>&nbsp;<span class='sm'>(see messages below)</span>" : "%d",
              cfg->nWarnings);

    htmlContent = Iirf_AllocAndSprintf(NULL,
                                       vdirStatusFormat,
                                       cfg->ApplMdPath,

                                       iniFileStyle,
                                       cfg->IniChain->Name,
                                       iniFileStyle,
                                       lastWrite,

                                       lastReadHdr,
                                       lastReadTime,

                                       cfg->nFiles,
                                       cfg->nLines,
                                       cfg->nRules,
                                       warningStyle,
                                       nWarnings,
                                       errorStyle,
                                       nErrors,

                                       logFileStyle,
                                       logFileMsg,
                                       cfg->LogFileName ? cfg->LogFileName : "(none)",

                                       cfg->LogLevel,
                                       (cfg->EngineOn) ? "ON" : "OFF",
                                       (cfg->RewriteBase) ? cfg->RewriteBase : "--",
                                       (cfg->AllowRemoteStatus) ? "enabled" : "disabled",

                                       cfg->CondSubstringBackrefFlag,
                                       cfg->ConversionFlagChar,

                                       (cfg->UrlDecoding) ? "ON" : "OFF",
                                       cfg->IterationLimit,
                                       cfg->ProxyTimeout[0],
                                       cfg->ProxyTimeout[1],
                                       cfg->ProxyTimeout[2],
                                       cfg->ProxyTimeout[3],
                                       cfg->numRequestsServed,
                                       allStatusMsgs ? allStatusMsgs : "");

    if (allStatusMsgs) free(allStatusMsgs);
    free(lastWrite);
    free(lastReadTime);
    free(nErrors);
    free(nWarnings);
    return htmlContent;

#undef IIRF_TSTR_LEN

}



/* This is used only when the IsapiRewriter library is being queried for its version.  */
/* This is never called from the ISAPI itself.  */
/* extern "C" */
char * Iirf_GetBuildSig()
{
    return gIirfBuildSig;
}


/* This is used only when the IsapiRewriter library is being queried for its version.  */
/* This is never called from the ISAPI itself.  */
/* extern "C" */
char * Iirf_GetVersion()
{
    return gIirfVersion;
}


int FormatUserAndGroups(CHAR** userName, CHAR **groupList)
{
    DWORD inSz = 0;
    DWORD outSz = 0;
    int i, j, C;
    LPTSTR grpName;
    LPTSTR domainName;
    DWORD grpSz = 0;
    DWORD domSz = 0;
    size_t totalSizeNeeded = 0;
    SID_NAME_USE nameUse;
    HANDLE h_Process;
    HANDLE h_Token;
    PSID_AND_ATTRIBUTES sidAndAttrs;
    // http://msdn.microsoft.com/en-us/library/aa379625.aspx
    TOKEN_GROUPS_AND_PRIVILEGES *grpsPrivs = NULL;

    h_Process = GetCurrentProcess();

    if (OpenProcessToken(h_Process,TOKEN_READ,&h_Token) == FALSE) {
        //printf("Error: Couldn't open the process token (E=%d)\n", GetLastError());
        return -1;
    }

    // get groups
    for (i=0; i < 2; i++) {
        if (GetTokenInformation(h_Token,
                               TokenGroupsAndPrivileges,
                               grpsPrivs,
                               inSz,
                               &outSz) == FALSE) {
            errno_t e = GetLastError();
            if (e == ERROR_INSUFFICIENT_BUFFER && i==0) {
                grpsPrivs = (TOKEN_GROUPS_AND_PRIVILEGES *) malloc(outSz);
                inSz = outSz;
            }
            else {
                // char eMsg[256];
                // _GenErrorMessage(e,eMsg,256);
                // printf("Error: GetTokenInformation: %s (E=%d)\n", eMsg, e);
                return -1;
            }
        }
    }

    grpSz = 1024;
    domSz = 1024;
    grpName = (LPTSTR) malloc(grpSz);
    domainName = (LPTSTR) malloc(domSz);
    C = grpsPrivs->SidCount;
    // first pass to count + allocate, 2nd pass to copy
    for (j=0; j < 2; j++) {
        for (i=0; i < C; i++) {
            sidAndAttrs = grpsPrivs->Sids + i;
            grpSz = 1024; // reset each cycle
            domSz = 1024;
            if (LookupAccountSid(NULL,
                                 sidAndAttrs->Sid,
                                 grpName,
                                 &grpSz,
                                 domainName,
                                 &domSz,
                                 &nameUse) == 0) {
                errno_t e = GetLastError();

                if (e != ERROR_NONE_MAPPED) {
                    //printf("  LookupAccountSid: Error E=%d\n", GetLastError());
                }
            }
            else if ((nameUse == SidTypeGroup) || (nameUse == SidTypeAlias) ||
                     (nameUse == SidTypeWellKnownGroup)) {
                if (j == 0) {
                    // accumulate (+ fudge)
                    totalSizeNeeded += strlen(grpName) + strlen(domainName) + 9;
                }
                else {
                    strcat_s(*groupList, totalSizeNeeded, domainName);
                    strcat_s(*groupList, totalSizeNeeded, "\\");
                    strcat_s(*groupList, totalSizeNeeded, grpName);
                    if (i < C-1)
                        strcat_s(*groupList, totalSizeNeeded, "<br/>\n");
                }
            }
            else if (nameUse == SidTypeUser) {
                // During pass 0, we don't need to accumulate a size for
                // the user name because there is only one user name.
                // So, only for pass 1, allocate and format the string.
                if (j == 1) {
                    size_t L = strlen(domainName) + strlen(grpName) + 3;
                    *userName = malloc(sizeof(char) * L);
                    *userName[0] = '\0';
                    strcat_s(*userName, L, domainName);
                    strcat_s(*userName, L, "\\");
                    strcat_s(*userName, L, grpName);
                }
            }
        }
        // allocate space
        if (j==0) {
            *groupList = malloc(totalSizeNeeded);
            *groupList[0] = '\0'; // initialize to the empty string
        }
    }

    free(grpName);
    free(domainName);
    free(grpsPrivs);
    return 0;
}




char * FormatGlobalStatus()
{
    SYSTEMTIME stRightNow ;
    char *rightNow = NULL, *htmlContent;
    char *userName = NULL;
    char *groupList = NULL;
    static const char * globalStatusFormat =
        "<h2>IIRF Global Status</h2>"
        "<table border='1px'>"
        "<tr><th>IIRF Version</th><td>%s</td></tr>\n"
        "<tr><th>Built on</th><td>%s</td></tr>\n"
        "<tr><th>Filter DLL</th><td>%s&nbsp;</td></tr>\n"
        "<tr><th>PCRE Version</th><td>%s</td></tr>\n"
        "<tr><th>IIRF User</th><td>%s</td></tr>\n"
        "<tr><th>Security Groups</th><td>%s</td></tr>\n"
        "<tr><th>IIRF Started</th><td>%s</td></tr>\n"
        "<tr><th>Current time</th><td>%s</td></tr>\n"
        "<tr><th>Server Ini file</th><td>%s&nbsp;</td></tr>\n"
        "<tr><th>Last Update of Ini</th><td>%s&nbsp;</td></tr>\n"
        "<tr><th>&nbsp;&nbsp;#Lines</th><td>%d</td></tr>\n"
        "<tr><th>&nbsp;&nbsp;#Warnings</th><td>%d</td></tr>\n"
        "<tr><th>Rewrite Engine (all vdirs)</th><td>%s</td></tr>\n"
        "</table>\n";

    if (gIirfStartupTime == NULL)
        gIirfStartupTime = Iirf_SystemTimeUtcToLocalTimeString(&(gFilterConfig->StartupTime));

    GetSystemTime(&(stRightNow));
    rightNow = Iirf_SystemTimeUtcToLocalTimeString(&(stRightNow));

    FormatUserAndGroups(&userName, &groupList);

    htmlContent = Iirf_AllocAndSprintf(NULL,
                                       globalStatusFormat,
                                       gIirfVersion,                     // ISAPI_FILTER_VERSION_STRING,
                                       Iirf_GetBuildSig(),
                                       gFilterConfig->DllLocation,       // full path of the DLL
                                       pcre_version(),
                                       userName, groupList,
                                       gIirfStartupTime,
                                       rightNow,                         // current time
                                       gFilterConfig->IniFileName,
                                       (gFilterConfig->IniLastUpdated)?gFilterConfig->IniLastUpdated:"???",
                                       gFilterConfig->nLines,
                                       gFilterConfig->nWarnings,
                                       (gFilterConfig->EngineOff) ? "OFF" : "ON");

    free(rightNow);
    if (userName != NULL) free(userName);
    if (groupList != NULL) free(groupList);
    return htmlContent;
}


// workitem 23459
DWORD _ReplyWithStatus(HTTP_FILTER_CONTEXT * pfc,
                       IirfVdirConfig * cfg,
                       char * method)
{
    char *szDate = Iirf_Rfc1123_DateTimeNow(), *addlHeaders;

    if (_stricmp(method, "OPTIONS")==0) {

        static const char *hdrFormat = "Content-Length: 0\r\n"
            "Content-Type: text/html\r\n"
            "Date: %s\r\n"
            "X-Powered-By: %s\r\n"
            "Allow: OPTIONS, GET\r\n"
            "Cache-Control: private,no-store,no-cache\r\n\r\n";

        addlHeaders = Iirf_AllocAndSprintf(NULL,
                                           hdrFormat, szDate, gIirfShortVersion);
        // emit the headers
        pfc->ServerSupportFunction (pfc,
                                    SF_REQ_SEND_RESPONSE_HEADER,
                                    (PVOID)"200 OK",
                                    (ULONG_PTR)addlHeaders,
                                    (ULONG_PTR) NULL );
    }
    else if (_stricmp(method, "GET")==0) {
        static const char *hdrFormat="Content-Length: %d\r\n"
            "Content-Type: text/html\r\n"
            "Date: %s\r\n"
            "X-Powered-By: %s\r\n"
            "Cache-Control: private,no-store,no-cache\r\n\r\n";
        static const char *htmlFormat = "<html><head><title>IIRF status</title>"
            "%s"
            "</head><body>"
            "<h1>IIRF Status Report</h1>"
            "%s\n"
            "%s\n"
            "</body></html>\n";

        int resplen;
        char *htmlContent,
            *globalStatusMsg = FormatGlobalStatus(),
            *vdirStatusMsg = FormatVdirStatus(cfg);

        // first, build the response
        htmlContent = Iirf_AllocAndSprintf(NULL,
                                           htmlFormat,
                                           gStyleMarkup,
                                           globalStatusMsg,
                                           vdirStatusMsg);

        // get the length of the response
        resplen = Iirf_ConvertSizeTo32bits(strlen(htmlContent));

        // embed that length into the header response
        addlHeaders = Iirf_AllocAndSprintf(NULL, hdrFormat, resplen, szDate, gIirfShortVersion);

        // emit the headers
        pfc->ServerSupportFunction (pfc,
                                    SF_REQ_SEND_RESPONSE_HEADER,
                                    (PVOID)"200 OK",
                                    (ULONG_PTR)addlHeaders,
                                    (ULONG_PTR) NULL );

        // emit the response
        pfc->WriteClient(pfc,(LPVOID)htmlContent, &resplen, 0);
        SetLastError( NO_ERROR );

        // clean up
        free (htmlContent);
        free (vdirStatusMsg);
        free (globalStatusMsg);
    }
    else {
        static const char * hdrFormat =
            "Content-Type: text/html\r\n"
            "Date: %s\r\n"
            "X-Powered-By: %s\r\n"
            "Allow: OPTIONS, GET\r\n\r\n";

        addlHeaders = Iirf_AllocAndSprintf(NULL, hdrFormat, szDate, gIirfShortVersion);

        // emit the headers
        pfc->ServerSupportFunction (pfc,
                                    SF_REQ_SEND_RESPONSE_HEADER,
                                    (PVOID)"405 Method Not Allowed",
                                    (ULONG_PTR)addlHeaders,
                                    (ULONG_PTR) NULL );
    }

    free (addlHeaders);
    free(szDate);
    return SF_STATUS_REQ_FINISHED;
}


DWORD _SetReply(HTTP_FILTER_CONTEXT * pfc, IirfVdirConfig * cfg, char * statusMsg)
{
    pfc->ServerSupportFunction (pfc,
                                SF_REQ_SEND_RESPONSE_HEADER,
                                (PVOID)statusMsg,
                                (ULONG_PTR)"Content-Length: 0\r\n"
                                "Content-Type: text/html\r\n\r\n",
                                (ULONG_PTR) NULL );

    SetLastError( NO_ERROR );
    LogMessage(cfg, 2, "DoRewrites: SetReply %s", statusMsg);
    return SF_STATUS_REQ_FINISHED;
}



DWORD _Forbidden(HTTP_FILTER_CONTEXT * pfc, IirfVdirConfig * cfg)
{
    return _SetReply(pfc,cfg,"403 Forbidden");
}

DWORD _NotFound(HTTP_FILTER_CONTEXT * pfc, IirfVdirConfig * cfg)
{
    return _SetReply(pfc,cfg,"404 Not Found");
}

DWORD _Gone(HTTP_FILTER_CONTEXT * pfc, IirfVdirConfig * cfg)
{
    return _SetReply(pfc,cfg,"410 Gone");
}

DWORD _BadRequest(HTTP_FILTER_CONTEXT * pfc, IirfVdirConfig * cfg)
{
    return _SetReply(pfc,cfg,"400 Bad Request");
}

DWORD _EntityTooLarge(HTTP_FILTER_CONTEXT * pfc, IirfVdirConfig * cfg)
{
    return _SetReply(pfc,cfg,"413 Request Entity Too Large");
}




DWORD DoRewrites(HTTP_FILTER_CONTEXT * pfc)
{
    DWORD returnValue= SF_STATUS_REQ_NEXT_NOTIFICATION;
    char *originalUriStem= NULL, *queryString= NULL, *originalUrl= NULL, *requestMethod= NULL;
    IirfRequestContext *ctx = (IirfRequestContext*) pfc->pFilterContext;
    IirfVdirConfig *cfg = GetVdirConfigFromFilterContext(pfc);

    LogMessage(cfg, 3, "DoRewrites");

    // Get the original URL.
    //
    // There are two issues here:
    //
    // 1. The URL needs to be normalized.
    //
    // According to http://support.microsoft.com/kb/896287 , apps should use
    // GetServerVariable to retrieve the *normalized* URL on IIS6 and above.
    // HowEVER, on IIS7, GSV("url") returns nothing.
    //
    // 2. IIS Logging
    //
    // In the OnLog handler, IIRF needs both the URI stem and the query path.
    // Therefore we need to record both separately here.
    //
    // As pointed out by workitem 11451
    // http://www.codeplex.com/IIRF/WorkItem/View.aspx?WorkItemId=11451
    //
    // ...IIS logging was not working properly.  With
    // the old mechanism, the cs-uri-stem logging field was really the entire
    // URI, and the cs-uri-query field was empty.
    //

    // get url
    originalUriStem =
        Iirf_IsapiStrdup(pfc,GetStashedHeader_AutoFree(pfc, "url"));

    if (originalUriStem == NULL) {
        LogMessage(cfg, 4, "DoRewrites: originalUriStem = NULL");
        returnValue= _NotFound(pfc, cfg);
        goto DoRewrites_Finished;
    }
    else {
        char * s =  (char *) strchr(originalUriStem, '?');
        // terminate the local copy of the URi at the question mark
        if (s != NULL) *s=0;
    }

    queryString= GetServerVariable_AutoFree(pfc, "QUERY_STRING");

    // get method
    requestMethod= GetHeader_AutoFree(pfc, "method");
    if (requestMethod== NULL) {
            returnValue= (GetLastError()== 122)
                ? _EntityTooLarge(pfc, cfg)
                : _BadRequest(pfc, cfg);
        goto DoRewrites_Finished;
    }

    originalUrl = SetRequestInfoInCustomFilterContext(pfc, originalUriStem, queryString, requestMethod);

    SetLastError( NO_ERROR );

    // see if we have a URL to rewrite:
    if (originalUrl[0]!='\0') {
        int rc;
        char *resultString, *undecodedUrl = NULL;
        RewriteRule *matchedRule;

        // workitem 23459
        InterlockedIncrement(&(cfg->numRequestsServed));

        if (cfg->UrlDecoding) {
            undecodedUrl = originalUrl;
            LogMessage(cfg, 4, "DoRewrites: New Url, before decoding: '%s' ", originalUrl);
            originalUrl = UrlDecode(originalUrl);  // allocates a new string
            LogMessage(cfg, 2, "DoRewrites: Url (decoded): '%s'", originalUrl);
        }
        else
            LogMessage(cfg, 2, "DoRewrites: Url: '%s'", originalUrl);

        rc= Iirf_EvaluateRules(pfc, originalUrl, 0, &matchedRule, &resultString);

        if (rc==0) { // no URL Rewrite result
            LogMessage(cfg, 2, "DoRewrites: No Rewrite");
            SetLastError( NO_ERROR );
        }
        else if (rc==1) { // Rewrite
            LogMessage(cfg, 2, "DoRewrites: Rewrite Url to: '%s'", resultString);
            ctx->AuthCompleteInfo->SetHeader(pfc, "url", resultString);
            // SsetHeader() copies the data, so we can free the ptr
            free(resultString);

            if (GetRecordOriginalUri(pfc)) {
                // Setting a header results in setting a server variable of
                // the same name, but prefixed by HTTP_ .  In this case we
                // will get HTTP_X_REWRITE_URL .  We set this to accomodate
                // server-side apps that want to know if the URL has been
                // rewritten.  ISAPI_Rewrite does this, and some people like
                // it.  Check the documentation for more info.
                // workitem 29558
                char * u = (cfg->UrlDecoding) ? undecodedUrl : originalUrl;

                ctx->AuthCompleteInfo->SetHeader(pfc, "X-Rewrite-Url:", u);
                LogMessage(cfg, 4, "DoRewrites: Record orig Url: '%s'", u);
            }

            SetLastError( NO_ERROR );
        }

        // workitem 23459
        else if (rc==1200) { // Inquire filter Status
            returnValue = _ReplyWithStatus(pfc, cfg, requestMethod);
        }

        else if (rc==1403) { // Forbidden
            returnValue= _Forbidden(pfc,cfg);
            free(resultString);
        }
        else if (rc==1404) { // Not found
            // workitem 19135
            returnValue= _NotFound(pfc,cfg);
            free(resultString);
        }
        else if (rc==1410) { // Gone
            returnValue= _Gone(pfc,cfg);
            free(resultString);
        }
        else if (rc==999) { // Proxy
            int chunks, totalBytes;
            // workitem 29415, 30598
            char *origHost= (matchedRule->ProxyPreserveHost)
                ? GetServerVariable(pfc, "HTTP_HOST")
                : NULL;

            if (matchedRule->ProxyPreserveHost) {
                LogMessage(cfg, 2, "DoRewrites: Proxy to: '%s' (preserve host '%s')",
                           resultString, origHost);
            }
            else
                LogMessage(cfg, 2, "DoRewrites: Proxy to: '%s'", resultString);

            if (IirfProxy_TryRelayEmptyBodyRequest(pfc, resultString, origHost, &chunks, &totalBytes)) {
                // This is a POST, will require a REWRITE to the Extension, then Proxy from there.
                //
                static const char *fmtString1=  "/proxy.iirf?path=%s&url=%s";
                static const char *fmtString2=  "/proxy.iirf?host=%s&path=%s&url=%s";

                // the (local) proxy URL.
                // This will get handled by the ISAPI Extension side.
                char *buf = (matchedRule->ProxyPreserveHost)
                    ? Iirf_AllocAndSprintf(NULL, fmtString2, origHost, cfg->ApplMdPath, resultString)
                    : Iirf_AllocAndSprintf(NULL, fmtString1, cfg->ApplMdPath, resultString);

                LogMessage(cfg, 2,"DoRewrites: internal rewrite to: '%s'", buf);

                // In the Extension, we have no way of getting the config
                // pointer, which is tied to the APPL_MD_PATH, or URL
                // path. And the extension needs the cfg pointer for Logging,
                // for example.  The functions to retrieve the vdir config
                // pointer all depend on the Filter context.  Which is a
                // drag. We're going to increment the RefCount on the existing
                // config, then pass the applmdpath to the extension.  The
                // extension will grab the cfg based on a string match search,
                // and then it'll be able to log messages.
                //
                // Cannot allow the extension to increment the refcount itself
                // because the filter context may be gone (And the config
                // reclaimed) by the time the extension is activated.
                //
                // The refcount can be safely decremented by the extension.
                //

                InterlockedIncrement(&(cfg->RefCount));

                ctx->AuthCompleteInfo->SetHeader(pfc, "url", buf);
                free(resultString);
                free(buf);
                if (GetRecordOriginalUri(pfc)) {
                    // Setting a header results in setting a server variable
                    // of the same name, but prefixed by HTTP_ .  In this case
                    // we will get HTTP_X_REWRITE_URL .
                    char *u = (cfg->UrlDecoding) ? undecodedUrl : originalUrl;
                    ctx->AuthCompleteInfo->SetHeader(pfc, "X-Rewrite-Url:", u);
                    LogMessage(cfg, 4, "DoRewrites: Record orig Url: '%s'", u);
                }

                if (origHost) free(origHost);

                SetLastError( NO_ERROR );
            }
            else
            {
                LogMessage(cfg, 3, "DoRewrites: Proxy complete: %d chunks, %d bytes'",
                           chunks, totalBytes);
                returnValue = SF_STATUS_REQ_FINISHED;
                free(resultString);
            }
        }
        else { // redirect
            char codestring[12];
            char *buf;   // the Modified Header
            rc-=1000;
            LogMessage(cfg, 2, "DoRewrites: Redirect (code=%d) Url to: '%s'", rc, resultString);

            if ( (_strnicmp(resultString,"http://", 7)==0) || (_strnicmp(resultString,"https://", 8)==0))
            {
                static const char * fmtString1=  "Location: %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                buf = Iirf_AllocAndSprintf(NULL, fmtString1, resultString);
            }
            else {
                char *serverName= GetServerVariable(pfc, "SERVER_NAME");
                char *serverPort= GetServerVariable(pfc, "SERVER_PORT");
                char *HTTPS= GetServerVariable(pfc, "HTTPS");
                char *protocol = (_strnicmp(HTTPS,"on",strlen(HTTPS)) ? "http" : "https");

                // workitem 17025
                // http://www.codeplex.com/IIRF/WorkItem/View.aspx?WorkItemId=17025
                // If we are using the default port for the protocol...
                if (((strcmp(serverPort,"80")==0) && (strcmp(protocol,"http")==0)) ||
                    ((strcmp(serverPort,"443")==0) && (strcmp(protocol,"https")==0)) ) {
                    static const char * fmtString1=  "Location: %s://%s%s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                    buf = Iirf_AllocAndSprintf(NULL, fmtString1, protocol, serverName, resultString);
                }
                else {
                    static const char * fmtString1= "Location: %s://%s:%s%s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                    buf = Iirf_AllocAndSprintf(NULL, fmtString1, protocol, serverName, serverPort, resultString);
                }
                free(serverName);
                free(serverPort);
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

            SetRequestInfoInCustomFilterContext(pfc, originalUriStem, queryString, requestMethod);

            free(resultString);
            free (buf);
            returnValue= SF_STATUS_REQ_FINISHED;
            SetLastError( NO_ERROR );
        }

        if (cfg->UrlDecoding)
            free(originalUrl);
    }


DoRewrites_Finished:
    {
        DWORD lastError= GetLastError();
        if (lastError != NO_ERROR && lastError != ERROR_FILE_NOT_FOUND) {
            returnValue = SF_STATUS_REQ_ERROR;
            LogMessage(cfg, 3, "DoRewrites: Finish. SF_STATUS_REQ_ERROR  LastError=%d", lastError);
        }
    }

    return returnValue;
}




DWORD OnAuthComplete ( HTTP_FILTER_CONTEXT            * pfc,
                       HTTP_FILTER_AUTH_COMPLETE_INFO * pACI )
{
    DWORD dwRetval = SF_STATUS_REQ_NEXT_NOTIFICATION;

    // Before we rewrite, we initialize the IirfRequestContext.

    // This prevents the incorrect use of OriginalUrl and RequestMethod in OnLog()
    // preserving PhysicalPath (from OnUrlMap()).
    if (pfc!=NULL && pfc->pFilterContext != NULL) {
        IirfRequestContext * ctx = (IirfRequestContext*) pfc->pFilterContext;
        ctx->OriginalUriStem     = NULL; // There is no free necessary, for any of
        ctx->QueryString         = NULL; // these pointers. They all hold pointers with
        ctx->RequestMethod       = NULL; // request-scoped allocation, and are automatically
        ctx->RequestUri          = NULL; // free'd by IIS when the request terminates.
        ctx->RecordOriginalUri   = FALSE;
        ctx->AuthCompleteInfo    = pACI;
    }

    // rewrite or redirect URL as desired
    dwRetval = DoRewrites(pfc);

    return dwRetval;
}



DWORD OnUrlMap (HTTP_FILTER_CONTEXT *pfc, HTTP_FILTER_URL_MAP * pUM)
{
    IirfRequestContext * ctx= NULL;
    int len;

    if (pfc==NULL)
        return SF_STATUS_REQ_NEXT_NOTIFICATION;  // nothing to do!

    // copy the physical path information. The pUM->pszPhysicalPath field may go out of scope
    // by the time the next notification comes by (OnAuthComplete)
    ctx = (IirfRequestContext *) pfc->pFilterContext;

    len = Iirf_ConvertSizeTo32bits(strlen(pUM->pszPhysicalPath) + 1); // less than or equal to pUM->cbPathBuff.
    if (ctx->PhysicalPath==NULL)
        ctx->PhysicalPath= (char *) pfc->AllocMem(pfc, len, 0);
    else {
        // the pointer has already been allocated and the path copied.
        // but we want to get the latest path, so we check here to see if
        // the existing pointer is sufficient.
        int len2 = Iirf_ConvertSizeTo32bits(strlen(ctx->PhysicalPath) +1);
        if (len2<len)
            // Alloc new memory if the existing pointer is insufficient capacity
            ctx->PhysicalPath= (char *) pfc->AllocMem(pfc, len, 0);
        else if (len2==len && strcmp(pUM->pszPhysicalPath,ctx->PhysicalPath)==0)
            // They are equal. No need to copy again.
            return SF_STATUS_REQ_NEXT_NOTIFICATION;
    }

    // catch all mem allocation failures
    if ( ctx->PhysicalPath == NULL ) {
        //LogMessage(1, "Error Allocating memory for Physical Path.");
        SetLastError( ERROR_NOT_ENOUGH_MEMORY );
        return SF_STATUS_REQ_ERROR ;
    }

    strcpy_s(ctx->PhysicalPath, len, pUM->pszPhysicalPath);

    return SF_STATUS_REQ_NEXT_NOTIFICATION;
}




DWORD OnLog( IN HTTP_FILTER_CONTEXT * pfc,
             IN HTTP_FILTER_LOG *     pLog )
{
    IirfVdirConfig * cfg;

    // log an unmangled URL if possible
    if (pfc->pFilterContext != NULL) {
        // means we have context
        IirfRequestContext *ctx = (IirfRequestContext *) pfc->pFilterContext;
        if (ctx->Magic == IIRF_CONTEXT_MAGIC_NUMBER) {

            // It is possible the context exists, but no OriginalUrl nor
            // RequestMethod was stored in it.
            if (ctx->RecordOriginalUri) {
                if (ctx->OriginalUriStem!=NULL) pLog->pszTarget =     (CHAR *)ctx->OriginalUriStem;
                if (ctx->QueryString!=NULL)     pLog->pszParameters = (CHAR *)ctx->QueryString;
                if (ctx->RequestMethod!=NULL)   pLog->pszOperation =  (CHAR *)ctx->RequestMethod;
            }

            // Decrement the reference count on the context, and potentially free it (if expired):
            cfg = GetVdirConfigFromFilterContext(pfc);
            ReleaseVdirConfig(cfg);
            ctx->VdirConfig = NULL;
            // reset the custom filter context:
            pfc->pFilterContext = NULL;

            // no need to free the ctx, because it is AllocMem'd which means auto-freed.
        }
    }
    return SF_STATUS_REQ_NEXT_NOTIFICATION;
}



DWORD OnEndOfRequest( IN HTTP_FILTER_CONTEXT * pfc )
{
    // if no logging is enabled, we release here.
    if (!gFilterConfig->WantNotifyLog) {
        // decrement the refcount on the context, and potentially free it
        IirfRequestContext *ctx = (IirfRequestContext *) pfc->pFilterContext;
        IirfVdirConfig * cfg = ctx->VdirConfig;
        ReleaseVdirConfig(cfg);
        ctx->VdirConfig= NULL;

        // reset the custom filter context:
        pfc->pFilterContext=NULL;
    }

    return SF_STATUS_REQ_NEXT_NOTIFICATION;
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
DWORD WINAPI HttpFilterProc( HTTP_FILTER_CONTEXT * pfc,
                             DWORD                 dwNotificationType,
                             VOID *                pvNotification )
{
    IirfVdirConfig * cfg;

    __try
    {
        TRACE("HttpFilterProc");

        if (pfc->pFilterContext==NULL && !InitCustomFilterContext(pfc))
            return SF_STATUS_REQ_ERROR ;

        switch ( dwNotificationType ) {

#if 0
            case SF_NOTIFY_PREPROC_HEADERS:
                cfg = GetVdirConfigFromFilterContextCheckUpdate(pfc);
                LogMessage(3, "HttpFilterProc: SF_NOTIFY_PREPROC_HEADERS");
                return OnPreprocHeaders(pfc, (HTTP_FILTER_PREPROC_HEADERS *) pvNotification );
                break;
#endif

            case SF_NOTIFY_URL_MAP:
                // This notification may happen multiple times within the scope
                // of a single HTTP request.
                TRACE("HttpFilterProc: NOTIFY_URL_MAP");
                cfg = GetVdirConfigFromFilterContext(pfc);
                LogMessage(cfg, 3, "HttpFilterProc: SF_NOTIFY_URL_MAP");
                LogMessage(cfg, 3, "HttpFilterProc: cfg= 0x%08X", cfg);
                return OnUrlMap(pfc, (HTTP_FILTER_URL_MAP *) pvNotification );
                break;

            case SF_NOTIFY_AUTH_COMPLETE:
                cfg = GetVdirConfigFromFilterContext(pfc);
                LogMessage(cfg, 3, "HttpFilterProc: SF_NOTIFY_AUTH_COMPLETE");
                return OnAuthComplete(pfc, (HTTP_FILTER_AUTH_COMPLETE_INFO *) pvNotification );
                break;

            case SF_NOTIFY_LOG:
                cfg = GetVdirConfigFromFilterContext(pfc);
                LogMessage(cfg, 3, "HttpFilterProc: SF_NOTIFY_LOG");
                return OnLog(pfc, (HTTP_FILTER_LOG *) pvNotification );
                break;

            case SF_NOTIFY_END_OF_REQUEST:
                // Here's the deal: At the end of every request, I want to decrement the reference
                // count on the configuration context.  END_OF_REQUEST is the natural time to do
                // that. BUT!  NOTIFY_LOG may come AFTER END_OF_REQUEST - I could not tell from the
                // way the ISAPI doc is written.  And we need the config context until after
                // NOTIFY_LOG, if NOTIFY_LOG is enabled. Remember, NOTIFY_LOG is optional and can
                // defeat/disable the Kernel-mode cache. So it is by default OFF.  Therefore, we'll
                // decrement the refcount on the context here in END_OF_REQUEST if no logging
                // notification is enabled.  We'll decrement the refcount on the context in
                // NOTIFY_LOG if logging IS enabled. Capisce?
                return OnEndOfRequest(pfc);
                break;

            default:
                cfg = GetVdirConfigFromFilterContext(pfc);
                LogMessage(cfg, 3, "HttpFilterProc: notification type: (%d)",dwNotificationType);
                break;
        }
    }
    __except ( ExceptionFilter(GetExceptionInformation(), GetVdirConfigFromFilterContext(pfc)))
    {
    }

    return SF_STATUS_REQ_NEXT_NOTIFICATION;
}





BOOL WINAPI TerminateFilter(DWORD dwFlags)
{
    /* free / unload / unlock any allocated/loaded/locked resources */
    return TRUE;
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
char * ReplaceServerVariables(PHTTP_FILTER_CONTEXT pfc, char *inputString)
{
    char *p1, *outString = NULL, *pOut = NULL, *strtokContext= NULL;
    boolean done = FALSE;
    int pass;
    size_t szOut = 0;
    IirfVdirConfig *cfg = GetVdirConfigFromFilterContext(pfc);

    if (inputString == NULL) return _strdup("");
    if (inputString[0] == '\0') return _strdup("");

    // Do this in two passes. First pass to count the length, 2nd to
    // actually do the copying. It needs to happen this way because we
    // use strtok to walk the string, and strtok() actually changes the
    // subject string.
    for (pass=0; pass < 2; pass++) {
        // get a copy of the input string
        char *myCopy= _strdup(inputString);
        p1= myCopy;

        while (p1[0]!='\0') {
            if ((pfc!=NULL) && (p1[0]=='%') && ( p1[1]=='{' )) {
                // we think we have a server variable
                // find word surrounded by ending braces
                char *variableName= strtok_s(p1+2, "}", &strtokContext);

                if (variableName != NULL) {
                    char *value= GetServerVariable(pfc, variableName);

                    if (pass==0) {
                        szOut += strlen(value);
                    }
                    else {
                        LogMessage(cfg, 5, "ReplaceServerVariables: vName(%s) value(%s)",
                                   variableName, value);

                        // workitem 19137
                        if(strcpy_s(pOut,szOut-(int)(pOut-outString), value)==0) {
                            pOut+= strlen(value);
                            *pOut='\0';
                        }
                    }

                    // advance the ptr to the closing brace.
                    // p1 will be advanced one more char, below.
                    p1+= strlen(variableName)+2;

                    free(value);
                }
                else {
                    LogMessage(cfg, 2, "ReplaceServerVariables: no variable name found (no end brace?)");
                    // badly formed string, undefined behavior.
                }
            }
            else {
                if (pass==0) {
                    szOut++;
                }
                else {
                    // copy that character through
                    *pOut= *p1;
                    pOut++;
                }
            }

            p1++;
        }
        if (pass == 0) {
            szOut++; // terminator
            LogMessage(cfg, 4, "ReplaceServerVariables: alloc %d bytes", szOut);
            pOut = outString = (char *) malloc(szOut+1);  // one to grow on
        }

        if (myCopy != NULL)
            free(myCopy);
    }
    *pOut='\0';

    LogMessage(cfg, 4, "ReplaceServerVariables: in='%s' out='%s'",
               inputString, outString);

    return outString;
}




/*
 * ApplyUrlEncoding
 *
 * Purpose:
 *
 *   Do URL Encoding as necessary. This fn
 *   handles #X..#E and URL-encodes everything in between.
 *
 * Arguments:
 *
 *   cfg - The Vdir Config entry (IirfVdirConfig) for the request.
 *
 *   s - the input string, a string that possibly contains #X and #E opcodes.
 *       It is assumed to have been allocated, and will be freed if
 *       necessary.
 *
 * Returns:
 *
 *   if no encoding was performed, the original string pointer;
 *   if encoding was performed, a newly-allocated string pointer.
 *
 */
char * ApplyUrlEncoding(IirfVdirConfig *cfg, char * s)
{
    char *p1, *start = NULL, *finish = NULL, *outString = s;
    char flagChar = cfg->ConversionFlagChar;  // default: '#'
    boolean encodingNecessary = FALSE;
    int pass;

    LogMessage(cfg, 4, "ApplyUrlEncoding: in '%s'", outString);

    // two passes: the first pass to check if URL encoding is necessary;
    // the second, optional pass, to do the encoding.
    for (pass=0; pass < 2; pass++) {
        p1 = s;
        while (p1[0]!='\0' && (pass==1 || encodingNecessary==FALSE)) {
            if (p1[0]==flagChar) {
                switch (p1[1]) {
                    case 'X':
                        if (start == NULL) start = p1;
                        break;
                    case 'E':
                        if (start != NULL) finish = p1;
                        break;
                }
            }
            if (start != NULL && finish != NULL) {
                if (pass == 0) {
                    encodingNecessary = TRUE;
                }
                else {
                    char * newString;
                    char * encoded;
                    size_t dwSize;
                    *start = '\0'; // terminate, temporarily
                    *finish = '\0'; // terminate, temporarily
                    encoded = UrlEncode(start+2);
                    // splice the encoded string into the original
                    dwSize= strlen(outString) + strlen(encoded) + strlen(finish+1);
                    newString = (char *) malloc(dwSize * sizeof(char));
                    strcpy_s(newString, dwSize, outString);
                    strcat_s(newString, dwSize, encoded);
                    // reset pointer to end of the encoded segment in the new string
                    p1 = newString + strlen(newString);
                    strcat_s(newString, dwSize, finish+2); // last segment
                    free(outString); // out with the old
                    outString = newString; // in with the new
                    free(encoded);
                }
                start = NULL;
                finish = NULL;
            }
            p1++;
        }
        if (!encodingNecessary) pass++; // skip second loop if possible
    }

    LogMessage(cfg, 3, "ApplyUrlEncoding: out '%s'", outString);

    return outString;
}



/*
 * ApplyCaseConversionInPlace
 *
 * Purpose:
 *
 *   Do case conversion (aka case folding) in the input string, It
 *   handles #L..#E and #U..#E as well as #l and #u as within PERL
 *   replacement strings. Because the output string can only be the same
 *   length as the input (in the case of no case folding) or shorter,
 *   conversion is done "in place."

 *   The opcode character needs to be something that no reasonable URL would
 *   contain. This is a a bit tricky, as any visible ASCII character is legal in
 *   a URL. By default, the # character is the flag char for case conversion.
 *   This may be changed via the FlagCharacters directive. The octothorpe
 *   is also used for referring to named anchor points in a web page. This
 *   will work as long as the referred anchor point does not begin with E, U, L,
 *   u, or l. You can escape the flag character by doubling it.
 *
 * Arguments:
 *
 *   cfg - The Vdir Config entry (IirfVdirConfig) for the request.
 *
 *   s - the input string, a string that possibly contains #U and #L opcodes.
 *
 * Returns:
 *
 *   the original string pointer, with case-folding opcodes removed and
 *   case folding performed.
 *
 */
void ApplyCaseConversionInPlace(IirfVdirConfig *cfg, char * s)
{
    char *pIn= s, *pOut= s;
    char state= 0, delta = ('a'-'A');
    char flagChar = cfg->ConversionFlagChar;  // default: '#'

    LogMessage(cfg, 6, "ApplyCaseConversion: before '%s'", s);

    while (pIn[0]!='\0') {

        if (pIn[0]==flagChar) { // previously, #
            switch (pIn[1]) {
                case 'L':
                    pIn++;
                    state=1; // lowercase
                    break;
                case 'U':
                    pIn++;
                    state=2; // uppercase
                    break;
                case 'E':
                    // workitem 31670
                    if (state!=0) {
                        pIn++;
                        state=0; // end conversion
                    }
                    else {
                        // We've seen no "open" for case conversion, but this is a
                        // "Close".  This is probably the end of a URL encoding
                        // conversion. Pass it through, it will be handled later in
                        // ApplyUrlEncoding().
                        *pOut= *pIn;
                        pOut++;  // advance to the next char on output
                    }
                    break;
                case 'l':
                    pIn++;
                    state=3; // lowercase one character
                    break;
                case 'u':
                    pIn++;
                    state=4; // uppercase one character
                    break;
                default:
                    // There is a flagChar followed by something that is not a
                    // case-conversion opcode character.
                    if (pIn[1]==flagChar && state==0) {
                        // doubled flag char - treat it as "escape"
                        pIn++;
                    }
                    // pass it through.
                    *pOut= *pIn;
                    pOut++;  // step to the next char on output
                    break;
            }
        }
        else {
            switch (state) {
                case 0:
                    // do nothing
                    break;
                case 1: // lowercase
                    if ((*pIn >='A') && (*pIn <= 'Z')) *pIn+= delta;
                    break;
                case 2: // uppercase
                    if ((*pIn >='a') && (*pIn <= 'z')) *pIn-= delta;
                    break;
                case 3: // lowercase one char
                    if ((*pIn >='A') && (*pIn <= 'Z')) *pIn+= delta;
                    state=0;
                    break;
                case 4: // uppercase one char
                    if ((*pIn >='a') && (*pIn <= 'z')) *pIn-= delta;
                    state=0;
                    break;
            }
            *pOut= *pIn;
            pOut++;  // step to the next char on output
        }
        pIn++;  // step to the next char on input
    }
    *pOut = '\0'; // terminate

    LogMessage(cfg, 6, "ApplyCaseConversion: after  '%s'", s);

}  // void ApplyCaseConversion(char * s)






char * MapKey(IirfVdirConfig *cfg, char *mapName, char *key )
{
    RewriteMap *m = cfg->rootMap;
    LogMessage(cfg, 4, "MapKey: map(%s) key(%s)", mapName, key);
    while (m != NULL) {
        LogMessage(cfg, 6, "MapKey: looking at map(%s)", m->name);
        if (strcmp(m->name, mapName)==0) {
            TextMap * textMap = m->u.textMap;
            TextMapItem *found;
            // found the right map
            LogMessage(cfg, 5, "MapKey: found map(%s) type(%d, %s)", m->name, m->type, (m->type==0)?"txt":(m->type==1)?"rnd":"???");
            // sanity check
            if (m->type!=0 &&  m->type!=1) { // not txt and not rnd?
                LogMessage(cfg, 3, "MapKey: map(%s) key(%s) map is of unknown type (%d) - bail", mapName, key, m->type);
                return NULL;
            }

            // workitem 31414: retrieve using bsearch
            found = (TextMapItem *) bsearch( &key,
                                             (void *) textMap->items,
                                             textMap->length,
                                             sizeof( TextMapItem ),
                                             (int (*)(const void*, const void*)) Iirf_FindMapItemByKey );

            if (found) {
                if (m->type==0) {
                    // txt
                    LogMessage(cfg, 4, "MapKey: txt value(%s)", found->value);
                    return found->value;
                }
                else {
                    // rnd
                    unsigned int n;
                    int ix;
                    char * v;
                    errno_t e = rand_s( &n );
                    n= (e != 0)
                        ? 0
                        : (unsigned int) ((double) n / (double) UINT_MAX * (found->nValues+1)) ;
                    ix = found->indexes[n];

                    v= &(found->value[ix]);

                    LogMessage(cfg, 4, "MapKey: rnd selected(%d) value(%s)", n, v);
                    return v;
                }
            }


            LogMessage(cfg, 3, "MapKey: map(%s) key(%s) no value found in %d entries", mapName, key, m->u.textMap->length);
            return NULL;
        }
        m = m->next;
    }

    LogMessage(cfg, 3, "MapKey: map(%s) key(%s) no map found", mapName, key);
    return NULL;
}



/*
 * GenerateReplacementString
 *
 * Purpose:
 *
 *     Generates a string using the given replacementPattern, and the vector of
 *     substring matches in the source string and any RewriteConds. It also does
 *     map substitutions. After all substitutions, apply case folding as
 *     indicated, and then url-encoding as indicated.  This fn is recursive: it is
 *     legal and supported to have multiple nested pairs of curly braces for
 *     map substitutions, or map keys that depend on back references, and so on.
 *
 * Arguments:
 *
 *     replacePattern - the pattern to use to generate the
 *         output string. Any $N will be replaced with the
 *         corresponding match substring from the source.
 *         Any *N will be replaced with the corresponding match
 *         substring from the most recently evaluated RewriteCond (Condition).
 *         Example:
 *              RewriteCond %{SERVER_NAME}          ([^\.]+)\.chiesa\.net$                [I]
 *              RewriteCond c:\Inetpub\wwwroot\%1   -d
 *              RewriteRule ^(.*)$                  /common/driver.aspx?url=$1&host=*1    [U,I,L]
 *
 *     ruleMatchResult - the match result from the RewriteRule.  This contains: the
 *         source strings, typically a URL like /foo/bar/wee.php; the MatchCount,
 *         an integer indicating the number of matched substrings found in the
 *         result; and SubstringIndexes, a vector of integers.  The vector of
 *         contains the start and end indexes of the matched substrings, where
 *         Index[2n] is the start position and Index[2n+1] the end position of
 *         substring n, within the corresponding source string.  None of these
 *         fields get modified herein.
 *
 *     condMatchResult - same as ruleMatchResult, but for the most recently evaluated
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
char * GenerateReplacementString(HTTP_FILTER_CONTEXT * pfc,
                                 IirfVdirConfig *cfg,
                                 char *replacePattern,
                                 PcreMatchResult * ruleMatchResult,
                                 PcreMatchResult * condMatchResult)
{
    char *p1, *outString= NULL, *pOut= NULL;
    boolean done= FALSE;
    size_t szOut = 0;
    int pass, i, j;
    char flagChar[2];
    PcreMatchResult *matchResult[2];

    // special case: check for "do nothing"
    if (replacePattern[0] =='-'  && replacePattern[1] =='\0' ) {
        IirfRequestContext *ctx = (IirfRequestContext *) pfc->pFilterContext;
        outString = _strdup(ctx->RequestUri);
        LogMessage(cfg, 4, "GenerateReplacementString: do nothing... '%s'", outString);
        return outString;
    }

    flagChar[0]='$';
    flagChar[1]= cfg->CondSubstringBackrefFlag;  // default: '%'
    matchResult[0]= ruleMatchResult;
    matchResult[1]= condMatchResult;

    // this stanza for logging only
    if ( cfg->LogLevel >= 6 ) {
        #define AUX_MSG_BUF_SZ 256
        char msgBuffer1[AUX_MSG_BUF_SZ];
        msgBuffer1[0]='\0';
        for (i=0; i < sizeof(matchResult)/sizeof(matchResult[0]); i++) {
            strcat_s(msgBuffer1,AUX_MSG_BUF_SZ,"[  ");
            for(j=0; j<matchResult[i]->MatchCount*2; j++) {
                char vecbuf[32];
                _itoa_s(matchResult[i]->SubstringIndexes[j], vecbuf, 32, 10 );
                if (strlen(vecbuf) > 0) strcat_s(msgBuffer1,AUX_MSG_BUF_SZ,vecbuf);
                else strcat_s(msgBuffer1,AUX_MSG_BUF_SZ,"??");
                strcat_s(msgBuffer1,AUX_MSG_BUF_SZ,", ");
            }
            msgBuffer1[strlen(msgBuffer1)-2]=']';
        }

        LogMessage(cfg, 6, "GenerateReplacementString: src='%s','%s' replacePattern='%s' vec=[%s] counts=%d,%d",
                   matchResult[0]->Subject,
                   matchResult[1]->Subject,
                   replacePattern,
                   msgBuffer1,
                   matchResult[0]->MatchCount,
                   matchResult[1]->MatchCount);
    }


    // here is where the work gets done
    for (pass=0; pass < 2; pass++) {
        // first pass counts bytes, then allocates space;
        // second pass does the actual copying.
        p1 = replacePattern;
        while (p1[0]!='\0') {
            // ix is a ternary value: either -1, 0, or 1.
            // =============================================
            // -1 indicates the char is not a flag char.
            //  0 = flag char for backref of the first type.
            //  1 = flag char for backref of the second type.
            //
            int ix= -1;
            if (p1[0]==flagChar[0]) ix=0;
            else if (p1[0]==flagChar[1]) ix=1;

            if ( (ix!=-1) && ( isdigit(p1[1]) )) {
                int n= atoi(p1+1);  // get the index of the back-ref. Eg, for '%2' it returns 2.
                if (n < matchResult[ix]->MatchCount) {
                    char *substringStart = matchResult[ix]->Subject + matchResult[ix]->SubstringIndexes[2*n];
                    int substringLength = matchResult[ix]->SubstringIndexes[2*n+1] - matchResult[ix]->SubstringIndexes[2*n];
                    if (pass == 0) {
                        szOut += substringLength;
                    }
                    else {
                        strncpy_s(pOut, szOut-(int)(pOut-outString), substringStart, substringLength);
                        LogMessage(cfg, 6, "GenerateReplacementString: replacing (%c%d) with '%s'", flagChar[ix], n, pOut);
                        pOut+= substringLength;
                    }
                }
                else {
                    // A backref is out of range.
                    // It will evaluate to the empty string.
                }

                // step over the number we found
                if (n>0) {
                    // determine the number of digits to skip
                    int skip = (int) log10((double)n) + 1;
                    p1+= skip;
                }
                else
                    p1++;
            }

            else if ( (ix==0) && ( p1[1] == '{')) {

                // try to apply a RewriteMap
                int nestedCurlyCount = 0;
                char *p3= p1+2;

                // find the matching close-curly. We allow
                // nesting because the map spec may contain a server variable
                // in the form %{VARNAME}.
                while((*p3 != '}' || nestedCurlyCount > 0) && (*p3 != '\0')) {
                    if (*p3 == '{') nestedCurlyCount++;
                    else if (*p3 == '}') nestedCurlyCount--;
                    p3++;
                }

                //          0123456789
                //        0123456789012
                //        ${mapname:$n}
                //        ^           ^
                // p1 ----|           |
                // p3 ----------------|
                //
                //
                //          0123456789012345678
                //        0123456789012345678901
                //        ${mapname:$n|NotFound}
                //        ^                    ^
                // p1 ----|                    |
                // p3 -------------------------|
                //

                LogMessage(cfg, 4, "GenerateReplacementString: map?");

                if (*p3 != '\0') {
                    // found a close-curly
                    ptrdiff_t len = p3 - p1 ;
                    char *strtokContext= NULL;
                    char *mapName, *valueToMap, *defaultValue;
                    char *mapSpec = (char *) malloc(len-1);
                    strncpy_s(mapSpec, len-1, p1+2, len-2);
                    mapSpec[len-1-1]='\0';  // terminate

                    mapName= strtok_s(mapSpec, ":", &strtokContext);
                    valueToMap= strtok_s(NULL, "|", &strtokContext);
                    defaultValue= strtok_s(NULL, "|", &strtokContext);

                    if (mapName == NULL || valueToMap == NULL) {
                        if (pass==0) {
                            szOut += len+2;
                        }
                        else {
                            // pass through the entire string
                            strncpy_s(pOut, szOut-(int)(pOut-outString), p1, len+1);
                            pOut+= len+2;
                            *pOut='\0';
                            LogMessage(cfg, 6, "GenerateReplacementString: map: missing mapname or reference.");
                        }
                    }
                    else {
                        int ix2 = -1;
                        char *key, *value;

                        LogMessage(cfg, 6, "GenerateReplacementString: mapName(%s) tomap(%s)",
                                   mapName, valueToMap);

                        // recurse: substitute back-references as appropriate.
                        key= GenerateReplacementString(pfc, cfg,
                                                       valueToMap,
                                                       ruleMatchResult,
                                                       condMatchResult);

                        value = MapKey(cfg, mapName, key);

                        LogMessage(cfg, 6, "GenerateReplacementString: map %s (%s)=>(%s)=>(%s)",
                                   mapName, valueToMap, key, value);

                        if (value == NULL) {
                            // the key was not found
                            if (defaultValue != NULL) {
                                // there's a default value
                                // iterate: substitute back-references in the default value, as appropriate.
                                char * dv = GenerateReplacementString(pfc, cfg,
                                                                      defaultValue,
                                                                      ruleMatchResult,
                                                                      condMatchResult);
                                LogMessage(cfg, 6, "GenerateReplacementString: use map's default value (%s)=>(%s)",
                                           defaultValue, dv);

                                if (pass==0) {
                                    szOut += strlen(dv);
                                }
                                else {
                                    LogMessage(cfg, 6, "GenerateReplacementString: map to default value (%s)", dv);
                                    strcpy_s(pOut, szOut-(int)(pOut-outString), dv);
                                    pOut+= strlen(dv);
                                }
                                free(dv);
                            }
                            else {
                                // there's no default value
                                size_t d = strlen(mapName) + 3;

                                if (pass==0) {
                                    szOut += d + strlen(key) + 1;
                                }
                                else {

                                    LogMessage(cfg, 6, "GenerateReplacementString: key(%s) not found", key);

                                    strncpy_s(pOut, szOut-(int)(pOut-outString), p1, d);
                                    pOut+= d;

                                    strncpy_s(pOut, szOut-(int)(pOut-outString), key, strlen(key));
                                    pOut+= strlen(key);
                                    *pOut='}';
                                    pOut++;
                                    *pOut='\0';
                                }
                            }
                        }
                        else {
                            // the key was found
                            if (pass==0) {
                                szOut += strlen(value);
                            }
                            else {
                                strcpy_s(pOut, szOut-(int)(pOut-outString), value);
                                pOut+= strlen(value);
                            }
                        }

                        free(key);
                    }

                    p1 += len;
                    free(mapSpec);
                }
                else {
                    // pass through one char
                    if (pass==0) {
                        szOut++;
                    }
                    else {
                        *pOut= *p1;
                        pOut++;
                    }
                }
            }

            else if ((ix!=-1) && (p1[0]==p1[1])) {
                // The character following the flagChar is not a digit.
                //
                // workitem 9910
                // allow % or $ in the output of the replacement string.  first
                // added in release v1.2.12a
                //
                // If the char is the same as the flag char, treat it like an
                // escape for the flag char.  The net effect is to reduce a
                // double-flagChar to a single-flagChar.

                if (pass==0) {
                    szOut++;
                }
                else {
                    // Copy the first flagChar to the output.
                    *pOut= *p1;
                    // Advance the pointer on the output buffer, one character.
                    pOut++;
                }
                // Skip one char on input; we'll skip the second flagChar in the input,
                // later after we fall through this loop.
                p1++;

            }
            else {
                // pass through
                if (pass==0) {
                    szOut++;
                }
                else {
                    *pOut= *p1;
                    pOut++;
                }
            }

            // step over the char, either ($ or %) or a non-flag char
            p1++;


            if (pass!=0) {
                // failsafe check for string full
                if (szOut <= (size_t)(pOut-outString)+1) {
                    // terminate
                    //outString[szOut-1]='\0';
                    *pOut = '\0';
                    LogMessage(cfg,
                               1,
                               "GenerateReplacementString: result too long?: delta(%d) sz(%d) s(%s)",
                               (pOut-outString),
                               szOut,
                               outString);
                    break;
                }
            }
        }

        if (pass == 0) {
            szOut+=2; // include space for terminator
            LogMessage(cfg, 4, "GenerateReplacementString: alloc %d bytes", szOut);
            pOut = outString = (char *) malloc(szOut);
        }
    }

    *pOut='\0';

    ApplyCaseConversionInPlace(cfg, outString);
    outString = ApplyUrlEncoding(cfg, outString);

    LogMessage(cfg, 4, "GenerateReplacementString: result '%s'", outString);

    return outString;
}




HANDLE MyGetFileInformation( char * fileName, BY_HANDLE_FILE_INFORMATION *pInfo)
{
    DWORD flags = FILE_FLAG_BACKUP_SEMANTICS
        | FILE_FLAG_OPEN_REPARSE_POINT;

    HANDLE hFile = CreateFile( fileName,                          // path
                               0, // GENERIC_READ,                // desired access
                               FILE_SHARE_READ|FILE_SHARE_DELETE, // for subsequent opens
                               NULL,                              // security attributes (NULL = default)
                               OPEN_EXISTING,                     // open but do not create
                               flags,
                               NULL
        );

    if (hFile != INVALID_HANDLE_VALUE)
        GetFileInformationByHandle (hFile, pInfo);

    return hFile;
}


// workitem 26705
boolean EvaluateLexicographicConditionVariant(IirfVdirConfig * cfg, RewriteCondition *cond, char * test)
{
    boolean retVal= FALSE;
    int (*comparator)(const char *s1, const char *s2) = (cond->IsCaseInsensitive)? _stricmp : strcmp;
    int value = comparator(test,cond->Pattern);
    switch (cond->SpecialConditionType) {
        case '<':
            retVal = (value < 0);
            break;
        case '>':
            retVal = (value > 0);
            break;
        case '=':
            retVal = (value == 0);
            break;
    }

    LogMessage(cfg, 4, "EvalCondition: Lexicographic variant, retVal= %s", retVal?"True":"false");
    return retVal;
}



boolean EvaluateFileConditionVariant(IirfVdirConfig * cfg, RewriteCondition *cond, char * path)
{
    boolean retVal= FALSE;

    // check for directory, file, or zero-length file
    BY_HANDLE_FILE_INFORMATION info;
    size_t last= strlen(path);
    HANDLE hFind;

    LogMessage(cfg, 4, "EvalCondition: cond->SpecialConditionType= '%c'",
               cond->SpecialConditionType);

    if (path[last-1]=='\\')
        path[last-1]='\0';

    hFind = MyGetFileInformation(path, &info);

    free(path);

    if (hFind == INVALID_HANDLE_VALUE) {
        // the given string is nothing
        retVal= FALSE;
        LogMessage(cfg, 5, "EvalCondition: Special: invalid path.");
    }
    else {
        // the handle is valid; it may be a file, a directory, or a link
        switch (cond->SpecialConditionType) {
            case 'd': // meaning: directory
                retVal= (boolean) (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
                // it may be a regular directory, or a junction.  Either is ok.
                LogMessage(cfg, 5, "EvalCondition: Special: is it a directory? (%s)", retVal?"yes":"no");
                break;

            case 'f': // meaning: file
                retVal= !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
                LogMessage(cfg, 5, "EvalCondition: Special: is it a file? (%s)", retVal?"yes":"no");
                break;

            case 's': // meaning:  regular file with non zero size
                // verify it is NOT a directory (ergo, a file), and verify that it has non-zero size
                retVal= (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                         !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                         ((info.nFileSizeHigh  != 0) || (info.nFileSizeLow != 0)));
                LogMessage(cfg, 5, "EvalCondition: Special: is it a non-zero sized file? (%s)", retVal?"yes":"no");
                break;

            case 'l': // meaning: symlink
            case 'j': // meaning: junction
                if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
                    DWORD bytesReturned = 0;
                    //DWORD L1 = sizeof(REPARSE_DATA_BUFFER);
                    DWORD L1 = 1024;
                    REPARSE_DATA_BUFFER * rdb = malloc(L1);
                    BOOL retVal;
                    BOOL rc = DeviceIoControl(
                        hFind,                   // handle to file or directory
                        FSCTL_GET_REPARSE_POINT, // dwIoControlCode
                        NULL,                    // lpInBuffer
                        0,                       // nInBufferSize
                        (LPVOID) rdb,            // output buffer
                        (DWORD) L1,              // size of output buffer
                        &bytesReturned,          // number of bytes returned
                        NULL                     // OVERLAPPED structure
                        );

                    if (rc == 0) {
                        int e = GetLastError();
                        char eMsg[256];
                        Iirf_GenErrorMessage(e, eMsg, 256);
                        LogMessage(cfg, 5, "EvalCondition: DeviceIoControl failed. %d %s",
                                   e, eMsg);
                        retVal= FALSE;
                    }
                    else {
                        retVal = (cond->SpecialConditionType == 'l')
                            ? (rdb->ReparseTag == IO_REPARSE_TAG_SYMLINK)
                            : ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                               (rdb->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT));
                    }
                    free(rdb);
                }
                else {
                    retVal= FALSE;
                }
                LogMessage(cfg, 5, "EvalCondition: Special: is it a %s? (%s)",
                           (cond->SpecialConditionType == 'l') ? "link" : "junction",
                           retVal?"yes":"no");
                break;

        }

        CloseHandle(hFind);
    }

    LogMessage(cfg, 4, "EvalCondition: Special variant, retVal= %s", retVal?"True":"false");
    return retVal;
}



boolean EvalCondition(HTTP_FILTER_CONTEXT * pfc,
                      PcreMatchResult * ruleMatchResult,
                      PcreMatchResult * condMatchResult,
                      RewriteCondition * cond)
{
    // check to see if the condition applies
    static char *FormatString1= "EvalCondition: t(%s) op(%c) p(%s)";
    char *ts1, *ts2;
    char op = (cond->SpecialConditionType!=0)?cond->SpecialConditionType:'~';
    boolean retVal = FALSE;
    IirfVdirConfig *cfg = GetVdirConfigFromFilterContext(pfc);

    LogMessage(cfg, 5, "EvalCondition: cond 0x%08X", cond);

    if (cond == NULL) return TRUE; // no condition exists, implies TRUE

    ts1= ReplaceServerVariables(pfc, cond->TestString);

    LogMessage(cfg, 5, "EvalCondition: ts1 '%s'", ts1);

    // Replace Back-references and map references.
    //
    // Back-refs are $n or *n references in the TestString; they get replaced by
    // the matched substrings from the respective subject strings. Also do map
    // substitutions. After all substitutions, do case conversion where directed,
    // and then url encoding.
    ts2= GenerateReplacementString(pfc, cfg, ts1, ruleMatchResult, condMatchResult);

    free(ts1);

    LogMessage(cfg, 5, FormatString1, ts2, op, cond->Pattern);

    // Strategy:  evaluate the condition, then apply the negation (if any) to the result.

    if ((cond->SpecialConditionType == 'd') ||
        (cond->SpecialConditionType == 'f') ||
        (cond->SpecialConditionType == 's') )
        retVal = EvaluateFileConditionVariant(cfg, cond, ts2);

    // workitem 26705
    else if ((cond->SpecialConditionType == '>') ||
        (cond->SpecialConditionType == '<') ||
        (cond->SpecialConditionType == '=') )
        retVal = EvaluateLexicographicConditionVariant(cfg, cond, ts2);

    else {
        // now test if ts2 matches the pattern for the RewriteCond
            int sz = Iirf_ConvertSizeTo32bits(strlen(ts2));
        // free any previously allocated Cond subject string
        if (condMatchResult->Subject) free(condMatchResult->Subject);

        condMatchResult->Subject= ts2;                   // will free this later

        condMatchResult->MatchCount =
            pcre_exec(cond->RE,                          // the compiled pattern
                      NULL,                              // no extra data - we didn't study the pattern
                      ts2,                               // the subject string
                      sz,                                // the length of the subject
                      0,                                 // start at offset 0 in the subject
                      0,                                 // default options
                      condMatchResult->SubstringIndexes, // pre-allocated output vector for substring position info
                      cfg->MaxMatchCount*3);             // number of elements allocated in the output vector

        // The condMatchResult will be used in any successive iterations for "back references" of the form %n

        if ( condMatchResult->MatchCount < 0) {
            if (condMatchResult->MatchCount == PCRE_ERROR_NOMATCH) {
                LogMessage(cfg, 5, "EvalCondition: match result: %d (No match)", condMatchResult->MatchCount );
            }
            else {
                LogMessage(cfg, 1, "EvalCondition: WARNING: match result: %d (unknown error)", condMatchResult->MatchCount);
            }
        }
        else {
            LogMessage(cfg, 5, "EvalCondition: match result: %d (match)", condMatchResult->MatchCount );
            retVal= TRUE;  // this condition evaluates to true
        }
    }

    // support ! prefix to negate
    if (cond->IsNegated) retVal = !retVal;

    LogMessage(cfg, 3, "EvalCondition: Cond t(%s) op(%c) p(%s) => %s",
               cond->TestString, op, cond->Pattern, retVal ? "TRUE" : "FALSE");

    // Follow the chain of additional conditions...
    if (cond->Child != NULL) {

        boolean MustEvaluateChild=
            (retVal && (cond->LogicalOperator==0)) ||  // first branch TRUE, AND operator
            (!retVal && (cond->LogicalOperator==1))  ;  // first branch FALSE, OR operator

        LogMessage(cfg, 5,"EvalCondition: Child is non NULL (parent= 0x%08X) (child= 0x%08X)", cond, cond->Child);

        // this stanza for logging only.
        // DANGER! we log separately from actually evaluating the MustEvaluateChild.
        // So there is in effect, redundant, parallel logic here, which may get de-synchronized.
        // Be careful modifying the above or the below.

        if ( cfg->LogLevel >= 5 ) {
            if (retVal) {
                // The current condition evaluates to TRUE.
                LogMessage(cfg, 5, "EvalCondition: Current condition evaluates to TRUE");

                // If the next Condition is linked by a logical 'OR', then no need to evaluate.
                // Since the first branch is TRUE, the OR of that branch with anything will be TRUE.

                // if the next Condition is linked by a logical 'AND', evaluate it.
                if (cond->LogicalOperator==0)  // AND
                    LogMessage(cfg, 5, "EvalCondition: Logical AND, ergo we evaluate the Child");
                else
                    LogMessage(cfg, 5, "EvalCondition: Logical OR, ergo no need to evaluate Child condition");
            }
            else {
                // The current condition evaluates to FALSE.
                LogMessage(cfg, 5, "EvalCondition: Current condition evaluates to FALSE");

                // If the next Condition is linked by a logical 'AND', then no need to evaluate.
                // Since the first branch is FALSE, the AND of that branch with anything will be FALSE.

                // OTOH, if the LogicalOperator is 'OR', then we must evaluate it.
                if (cond->LogicalOperator==1) // OR
                    LogMessage(cfg, 5, "EvalCondition: Logical OR, ergo we evaluate the Child");
                else
                    LogMessage(cfg, 5, "EvalCondition: Logical AND, ergo no need to evaluate Child condition");

            }
        }

        if (MustEvaluateChild)
            retVal = EvalCondition(pfc,
                                   ruleMatchResult,
                                   condMatchResult,
                                   cond->Child);
    }
    else
        LogMessage(cfg, 6, "EvalCondition: Child is NULL");


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
 * EvalConditionList
 *
 * Purpose:
 *
 *     evaluate a condition list, return true or false.
 *
 * Arguments:
 *
 *     pfc - filter context.  This is used to get to Server variables.
 *         The Condition may include referece to Server variables.
 *
 *     ruleMatchResult - the match result from the RewriteRule.  This
 *         contains: the source strings, typically a URL like
 *         /foo/bar/wee.php; the MatchCount, an integer indicating the number
 *         of matched substrings found in the result; and SubstringIndexes, a
 *         vector of integers.  The vector of contains the start and end
 *         indexes of the matched substrings, where Index[2n] is the start
 *         position and Index[2n+1] the end position of substring n, within
 *         the corresponding source string.  None of these fields get modified
 *         inside this procedure.
 *
 *     condMatchResult - same as ruleMatchResult, but this match result
 *         applies to the most recently evaluated Condition. (This may or may
 *         not be the RewriteCond positionally nearest the RewriteRule.  Due
 *         to logical precedence, RewriteCond's are not necessarily evaluated
 *         in the order in which they appear in the ini file, and it may be
 *         that not all RewriteCond's listed in the file are evaluated at
 *         runtime.)  This structure is filled in by this procedure, if the
 *         return value is true.  If the return value is false, then the
 *         condMatchResult is not meaningful.
 *
 *
 * Side Effects:
 *
 *     If the condition chain evaluates to true, then this procedure allocates
 *     memory for storing the Condition result (condMatchResult). The caller
 *     must free this memory later, via FreeMatchResult().  If the condition
 *     chain evaluates to false, the caller does not need to free
 *     condMatchResult.
 *
 *
 * Returns:
 *
 *     true or false.
 *
 */
boolean EvalConditionList(IirfVdirConfig *cfg,
                          HTTP_FILTER_CONTEXT * pfc,
                          int ruleNum,
                          PcreMatchResult *ruleMatchResult,
                          /* out */ PcreMatchResult *condMatchResult,
                          RewriteCondition * rootCondition)
{
    boolean result= FALSE;
    if (rootCondition == NULL) {
        // no condition exists, implies the rule will always apply.
        LogMessage(cfg, 3, "EvalConditionList: rule %d,  rootCondition is NULL => TRUE, Rule will apply", ruleNum);
        return TRUE;
    }

    // IIRF is going to evaluate one or more conditions, so it's necessary to
    // initialize and allocate space for out results.  The PCRE doc says
    // vector length should be 3n, where n is the max number of captures
    // recorded when matching against a single subject string.  The first 2/3
    // of that vector is used to return The first two-thirds of the vector is
    // used to pass back captured sub- strings, each substring using a pair of
    // integers to indicate the start and the length of the captured
    // substring. . The remaining third of the vector is used as workspace by
    // pcre_exec() while matching capturing subpatterns, and is not available
    // for passing back information.  The number passed in ovecsize should
    // always be a multiple of three. If it is not, it is rounded down.
    condMatchResult->SubstringIndexes= (int *) malloc((cfg->MaxMatchCount*3)*sizeof(int));
    condMatchResult->Subject= NULL;
    condMatchResult->MatchCount= 0;

    // EvalCondition walks the Condition tree
    result= EvalCondition(pfc,
                          ruleMatchResult,
                          condMatchResult,
                          rootCondition);

    LogMessage(cfg, 3, "EvalConditionList: rule %d, %s",
               ruleNum, result ? "TRUE, Rule will apply" : "FALSE, Rule does not apply");

    // WorkItem URL:  http://www.codeplex.com/IIRF/WorkItem/View.aspx?WorkItemId=9858

    // free condMatchResult->SubstringIndexes here in the case that the result
    // is false (rule does not apply)
    if (!result) FreeMatchResult(condMatchResult);

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
char * AppendQueryString(HTTP_FILTER_CONTEXT * pfc, char *rewrittenUrl)
{
    // workitem 19486
    char *originalQuerystring= GetServerVariable(pfc, "QUERY_STRING");

    if (originalQuerystring[0] == '\0') {
        // nothing to do
        free(originalQuerystring);
        return rewrittenUrl;
    }

    {
        // at this point we know there is an original query string, and
        // a rewritten URL.

        // is there a question mark in the rewritten URL?
        char * s =  (char *) strchr(rewrittenUrl, '?');

        // add ? if necessary, else use & separator
        char marker= (s != NULL) ? '&' : '?' ;

        // if the original URL ends in a ?, then the appended URL will end in a &
        char *newString = Iirf_AllocAndSprintf(NULL, "%s%c%s", rewrittenUrl, marker, originalQuerystring);

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
    HTTP_FILTER_CONTEXT *pfc,
    IirfVdirConfig *cfg)
{
    char *remoteAddr, *localAddr;
    boolean result= FALSE;
    if (cfg->AllowRemoteStatus) return TRUE;

    remoteAddr= GetServerVariable(pfc, "REMOTE_ADDR");
    localAddr= GetServerVariable(pfc, "LOCAL_ADDR");
    if (strncmp(remoteAddr, localAddr, strlen(localAddr)) == 0)
        result= TRUE;

    free (localAddr);
    free (remoteAddr);

    return result;
}




// must export this to allow the test driver to work
// EXPORT
int Iirf_EvaluateRules( HTTP_FILTER_CONTEXT * pfc,
                        char * OrigUri,
                        int depth,
                        /* out */ RewriteRule ** matchedRule,
                        /* out */ char ** resultUri)
{
    IirfRequestContext *ctx = (IirfRequestContext*) pfc->pFilterContext;
    IirfVdirConfig *cfg = GetVdirConfigFromFilterContext(pfc);
    RewriteRule *rule = cfg->rootRule;
    int retVal = 0,  // 0 = do nothing, 1 = rewrite, 403 = forbidden, other = redirect
        c = 0, sz, RuleMatchCount;
    int *RuleMatchVector;
    char *subject, *urlSubject = NULL, *hdrSubject = NULL;

#if ARTIFICIAL_FAIL
    char * artificialFailUrl = "/artificialFail";
#endif
    LogMessage(cfg, 3, "EvaluateRules: depth=%d", depth);

    // workitem 23459
    if (gFilterConfig->EnableStatusInquiry && (cfg->StatusUrl != NULL)) {
        if (strlen(OrigUri) >= strlen(cfg->StatusUrl) &&
            _strnicmp(OrigUri, cfg->StatusUrl, strlen(cfg->StatusUrl))==0 &&
            (OrigUri[strlen(cfg->StatusUrl)] == '?' || OrigUri[strlen(cfg->StatusUrl)] == '\0')) {
            // caller is requesting IIRF status
            if (StatusRequestAuthorized(pfc, cfg)) {
                LogMessage(cfg, 3, "EvaluateRules: status inquiry");
                *resultUri= NULL;
                return 1200;
            }
            else LogMessage(cfg, 3, "EvaluateRules: status inquiry, not authorized. Will process request as normal.");
        }
    }

    // workitem 23458
    if (gFilterConfig->EngineOff) {
        LogMessage(cfg, 4, "EvaluateRules: global Engine OFF, no action");
        return 0;
    }

    if (!cfg->EngineOn) {
        LogMessage(cfg, 4, "EvaluateRules: vdir Engine OFF, no action");
        return 0;
    }

    // workitem 26899
    subject= GetServerVariable(pfc, "SCRIPT_NAME");
    if (strcmp(subject + strlen(subject) - 5, ".iirf")==0) {
        free(subject);
        return 0;
    }
    free(subject);


#if ARTIFICIAL_FAIL
    // artificial fail
    if (strlen(OrigUri) >= strlen(artificialFailUrl)
        && _strnicmp(OrigUri+strlen(OrigUri)-strlen(artificialFailUrl), artificialFailUrl, strlen(artificialFailUrl))==0) {
        // caller is requesting a failure injection
        char * failPtr = (char *) 0;
        // This will fail with an Access Violation
        LogMessage(cfg, 1, "EvaluateRules: request for artificial failure");
        (*failPtr) = 8;
        // not reached
        return 1200;
    }
#endif

    if (rule==NULL) {
        LogMessage(cfg, 2, "EvaluateRules: No rewrite rules available.");
        return 0;
    }


    // The PCRE doc says vector length should be 3n.  The first 2*n
    // slots are used for returning data, the next n slots are used
    // internally by PCRE for temp storage.
    //
    // This space cannot be allocated on a per-rule basis; it must be
    // per-config in order to handle parallel requests.
    ///
    RuleMatchVector= (int *) malloc((cfg->MaxMatchCount*3)*sizeof(int));

    // The way it works:  First we evaluate the URL request, against the RewriteRule pattern.
    // If there is a match, then the logic evaluates the Conditions attached to the rule.
    // This may seem counter-intuitive, since the Conditions appear BEFORE the rule in the file.
    // The Rule is evaluated FIRST.

    // TODO: employ a circular buffer MRU cache for mapped URLs?

    while (rule!=NULL) {
        c++;

        if (rule->HeaderToRewrite != NULL) {
            // workitem 29172 - do not cache hdrSubject across rules
            hdrSubject = GetHeader_AutoFree(pfc, rule->HeaderToRewrite);
            LogMessage(cfg, 3, "EvaluateRules: subject is Header %s", rule->HeaderToRewrite);
            if (hdrSubject == NULL) {
                LogMessage(cfg, 3, "EvaluateRules: Header %s evaluates to nothing", rule->HeaderToRewrite);
                hdrSubject= "";
            }
            subject= hdrSubject;
        }
        else {
            if (urlSubject == NULL) {
                urlSubject = OrigUri;

                // workitem 26693
                if (cfg->RewriteBase == NULL) {
                    if (c==1) // only for first rule
                        LogMessage(cfg, 3, "EvaluateRules: no RewriteBase");
                }
                else if (cfg->RewriteBase[0]=='\0') {
                    if (c==1) // only for first rule
                        LogMessage(cfg, 3, "EvaluateRules: RewriteBase is empty (root vdir)");
                }
                else if (_strnicmp(OrigUri, cfg->RewriteBase, strlen(cfg->RewriteBase))==0) {
                    urlSubject += strlen(cfg->RewriteBase);
                    if (c==1) // only for first rule
                        LogMessage(cfg, 3, "EvaluateRules: stripping URL base, new subject: (%s)", urlSubject);
                }
                else {
                    if (c==1) // only for first rule
                        LogMessage(cfg, 3, "EvaluateRules: URL does not begin with RewriteBase string(%s), not stripping it.",
                                   cfg->RewriteBase);
                }
            }

            subject = urlSubject;
        }

        LogMessage(cfg, 4, "EvaluateRules: Rule %d: pattern: %s  subject: %s",
                   c, rule->Pattern, subject);
        sz = Iirf_ConvertSizeTo32bits(strlen(subject));
        RuleMatchCount = pcre_exec(
            rule->RE,              // the compiled pattern
            NULL,                  // no extra data - we didn't study the pattern
            subject,               // the subject string
            sz,                    // the length of the subject
            0,                     // start at offset 0 in the subject
            0,                     // default options
            RuleMatchVector,       // output vector for substring position information
            cfg->MaxMatchCount*3); // number of elements in the output vector

        // return code: >=0 means number of matches, <0 means error

        if (RuleMatchCount < 0) {
            if (RuleMatchCount== PCRE_ERROR_NOMATCH) {
                LogMessage(cfg, 3, "EvaluateRules: Rule %d: %d (No match)", c, RuleMatchCount );
            }
            else {
                LogMessage(cfg, 2, "EvaluateRules: Rule %d: %d (unknown error)", c, RuleMatchCount);
            }
        }
        else if (RuleMatchCount == 0) {
            LogMessage(cfg, 2, "EvaluateRules: Rule %d: %d (The output vector (%d slots) was not large enough)",
                       c, RuleMatchCount, cfg->MaxMatchCount*3);
        }
        else {
            // we have a match and we have substrings
            boolean conditionResult= FALSE;

            PcreMatchResult ruleMatchResult;
            PcreMatchResult condMatchResult;

            LogMessage(cfg, 3, "EvaluateRules: Rule %d: %d match%s",
                       c, RuleMatchCount, (c==1)?"":"es");

            // easier to pass these as a structure
            ruleMatchResult.Subject= subject;
            ruleMatchResult.SubstringIndexes= RuleMatchVector;
            ruleMatchResult.MatchCount= RuleMatchCount;

            // The fields in condMatchResult may be filled by the EvalConditionList(), but
            // we must init them because the EvalConditionList may never be called.  The
            // results reflect only the "last" Condition evaluated.  This may or may not be
            // the final Condition in the file; the evaluation engine won't evaluate
            // Conditions unnecessarily.  Check the readme for more details.
            condMatchResult.Subject= NULL;
            condMatchResult.SubstringIndexes= NULL;
            condMatchResult.MatchCount= 0;

            // get the result of evaluating the condition list, or TRUE if there is none.
            conditionResult= (rule->Condition==NULL);
            if (!conditionResult) {
                LogMessage(cfg, 3, "EvaluateRules: Rule %d: evaluating condition", c);
                conditionResult = EvalConditionList(cfg, pfc,
                                                    c,
                                                    &ruleMatchResult,
                                                    &condMatchResult,
                                                    rule->Condition);
            }


            // Check that any associated Condition evaluates to true, before
            // applying this rule.
            if ( conditionResult ) {
                *matchedRule = rule;
                // workitem 19136
                if (rule->IsForbidden) {
                    // no recurse
                    *resultUri= NULL;
                    retVal = 1403; //  = forbidden
                }
                else if (rule->IsNotFound) {
                    // no recurse
                    *resultUri= NULL;
                    retVal = 1404; //  = not found
                }
                else if (rule->IsGone) {
                    // no recurse
                    *resultUri= NULL;
                    retVal = 1410; //  = Gone
                }
                else {
                    // we are rewriting, redirecting, or proxying the URL, or rewriting a header.
                    // create the replacement string

                    char *ts1;
                    char *newString;

                    // generate the replacement string
                    // step 1: substitute server variables, if any.
                    ts1= ReplaceServerVariables(pfc, rule->Replacement);

                    // step 1: substitute back-references as appropriate.
                    newString= GenerateReplacementString(pfc,
                                                         cfg,
                                                         ts1,
                                                         &ruleMatchResult,
                                                         &condMatchResult);
                    free(ts1);
                    FreeMatchResult(&condMatchResult);

                    // workitem 26693 - apply QSA to RewriteHeader as well as the others.
                    // workitem 19486 - QSA modifier
                    if (newString!= NULL && rule->QueryStringAppend) {
                        char * orig = newString;
                        newString = AppendQueryString(pfc, newString);
                        if (newString != orig) free(orig);
                    }

                    // set output params
                    if (rule->HeaderToRewrite != NULL) {
                        if (pfc!=NULL && ctx->AuthCompleteInfo!=NULL) {
                            boolean retVal;
                            LogMessage(cfg, 3, "EvaluateRules: Setting Header: '%s' = '%s'", rule->HeaderToRewrite, newString);

                            retVal= ctx->AuthCompleteInfo->SetHeader(pfc, rule->HeaderToRewrite, newString);
                            if (!retVal) {
                                int e = GetLastError();
                                char eMsg[256];
                                Iirf_GenErrorMessage(e, eMsg, 256);
                                LogMessage(cfg, 2, "EvaluateRules: Failed Setting Header: error %d, %s", e, eMsg);
                            }

                            // stash if necessary
                            StashHeader(pfc, rule->HeaderToRewrite, newString);
                        }
                        else {
                            // happens only in testing
                            LogMessage(cfg, 4, "EvaluateRules: Want-to-but-cannot Set-Header: '%s' = '%s'",
                                       rule->HeaderToRewrite, newString);
                        }
                        free(newString);
                        newString = NULL;
                    }
                    else {
                        // We are rewriting, redirecting, or proxying the URL.
                        if ((rule->RuleFlavor == FLAVOR_RW_URL &&                                      // If (is Rewrite and
                             (rule->Replacement[0]!='-' || rule->Replacement[1]!='\0')) ||             //    not unchanged),  OR
                            (rule->RuleFlavor == FLAVOR_REDIRECT && newString[0]=='/')) {              // (is Redirect and replcmt begins with / (not http))
                            if (cfg->RewriteBase != NULL && cfg->RewriteBase[0]!='\0'  &&              // If we have a RewriteBase, AND
                                (_strnicmp(OrigUri, cfg->RewriteBase, strlen(cfg->RewriteBase))==0)) { // RewriteBase matches the OrigUri
                                // re-apply the base URL
                                char * orig = newString;
                                // but do not double slash
                                int delta = (((cfg->RewriteBase[0]=='/' && cfg->RewriteBase[1]=='\0') ||
                                             cfg->RewriteBase[strlen(cfg->RewriteBase)-1]=='/')
                                    && newString[0]=='/')
                                ? 1 : 0;

                                newString = Iirf_AllocAndConcatenate(cfg->RewriteBase, newString+delta);
                                free(orig);
                                LogMessage(cfg, 4, "EvaluateRules: prepend URL Base to result");
                            }
                        }

                        LogMessage(cfg, 3,"EvaluateRules: Result (length %d): %s", strlen(newString), newString);
                        *resultUri= newString;
                    }

                    // If the rule rule asks to record the original URL, then set the flag.
                    if (rule->RecordOriginalUrl)
                        SetRecordOriginalUri(pfc);

                    // check modifiers
                    if (rule->RuleFlavor == FLAVOR_REDIRECT) {
                        retVal = 1000 + rule->RedirectCode;  // = redirect
                    }
                    else if (rule->RuleFlavor == FLAVOR_PROXY) {
                        retVal = 999; // = proxy
                    }
                    else {
                        // rewrite url or rewrite header
                        retVal= (rule->HeaderToRewrite != NULL) ? 0 : 1;  // 0 = header, 1 = url
                        if (rule->IsLastIfMatch) {
                            // no iteration
                            LogMessage(cfg, 2, "EvaluateRules: Last Rule");
                            break;
                        }
                        // WorkItem 26212
                        if (rule->IsNoIteration) {
                            LogMessage(cfg, 2, "EvaluateRules: No iteration, go to the next rule");
                            // Go to the next rule.
                            rule= rule->next;
                            continue;
                        }

                        // by default, IIRF iterates on the RewriteRules.
                        if (depth < cfg->IterationLimit) {
                            char * t;
                            int rv;
                            subject = (rule->HeaderToRewrite != NULL) ? OrigUri : newString;

                            // workitem 26976
                            if (subject != OrigUri) {
                                // We are not rewriting an arbitrary header.

                                // I think this is ineffectual.
                                // ctx->AuthCompleteInfo->SetHeader(pfc, "url", subject);

                                // It's unnecessary to write the final value into the URL
                                // header, until the chain of calls to EvaluateRules()
                                // unwinds.  DoRewrites() will take care of that. Here,
                                // for future iterations of Iirf_EvaluateRules, we
                                // "stash" the URL.  If %{URL} is referenced in a
                                // replacement string or in a RewriteCond, IIRF will
                                // correctly retrieve from the stash, via a check in
                                // GetServerVariable().
                                StashHeader(pfc, "url", subject);
                            }

                            rv= Iirf_EvaluateRules(pfc, subject, depth+1, matchedRule, &t);
                            if (rv) {
                                *resultUri= t;  // a newly allocated string
                                retVal= rv;  // for return to caller

                                // if we've rewritten in a later rule, free our string, we no longer need it.
                                if (newString != NULL)
                                    free(newString);
                            }
                            // else, no match on recursion, so don't free newString.
                            // keep the existing result.
                        }
                        else {
                            LogMessage(cfg, 2, "EvaluateRules: Iteration stopped; reached limit of %d cycles.",
                                       cfg->IterationLimit);
                        }

                    }
                }
                break;  // break out of while loop on the first match
            }
        }

        // We did not break out of the loop.
        // Therefore, this rule did not apply.
        // Therefore, go to the next rule.
        rule= rule->next;
        hdrSubject = NULL;
    }

    free(RuleMatchVector);

    LogMessage(cfg, 3,"EvaluateRules: returning %d", retVal);
    return retVal;
}





void StashHeader(HTTP_FILTER_CONTEXT * pfc, char * variableName, char * value )
{
    // IirfVdirConfig * cfg = GetVdirConfigFromFilterContext(pfc);
    // LogMessage(cfg, 4, "StashHeader:  %s=%s", variableName, value);

    if (_stricmp(variableName, "URL")==0) {
        IirfRequestContext * ctx = (IirfRequestContext*) pfc->pFilterContext;
        ctx->InterimUrl = Iirf_IsapiStrdup(pfc, value);
    }
    else if (_stricmp(variableName, "METHOD")==0) {
        IirfRequestContext * ctx = (IirfRequestContext*) pfc->pFilterContext;
        ctx->InterimMethod = Iirf_IsapiStrdup(pfc, value);
    }
    // else do nothing
}



char * GetStashedHeader_AutoFree(HTTP_FILTER_CONTEXT * pfc, char * variableName )
{
    IirfRequestContext *ctx = (IirfRequestContext*) pfc->pFilterContext;
    // don't need to copy, because the stashed value is AllocMem'd
    if (_stricmp(variableName, "URL")==0) {
        if (ctx->InterimUrl == NULL)
            ctx->InterimUrl = GetHeader_AutoFree(pfc, "url");

        // return the same pointer for many calls
        return ctx->InterimUrl;
    }
    else if (_stricmp(variableName, "METHOD")==0) {
        if (ctx->InterimMethod == NULL)
            ctx->InterimMethod = GetHeader_AutoFree(pfc, "method");

        // return the same pointer for many calls
        return ctx->InterimMethod;
    }

    // should never happen
    return NULL;
}



// workitem 30399 - TIME psuedo variables
typedef struct _TimeVarSet  {
    char * Name;
    char * Fmt;
    short Length;
} TimeVarSet;


static const TimeVarSet TimeVars[] = {
    { "TIME_YEAR", "%Y", 5},
    { "TIME_MON",  "%m", 3},
    { "TIME_DAY",  "%d", 3},
    { "TIME_HOUR", "%H", 3},
    { "TIME_MIN",  "%M", 3},
    { "TIME_SEC",  "%S", 3},
    { "TIME_WDAY", "%w", 2},
    { "TIME_WEEK", "%U", 3},
    { "TIME_YDAY", "%j", 4},
    { "TIME",      "%Y%m%d%H%M%S", 15}
};




BOOL GetTimeVariable(char * variableName, CHAR ** ppszBuf)
{
    const int _MAX_TIME_BUF = 15;
    int i;
    for (i=0; i < sizeof(TimeVars)/sizeof(TimeVars[0]); i++) {
        if (strcmp(variableName, TimeVars[i].Name) == 0) {
            char * buf = malloc(_MAX_TIME_BUF);
            time_t t;
            struct tm tm;
            time(&t);
            localtime_s(&tm, &t);
            strftime(buf, TimeVars[i].Length, TimeVars[i].Fmt, &tm);
            (*ppszBuf) = buf;
            return TRUE;
        }
    }

    return FALSE;
}




char * GetServerVariable (HTTP_FILTER_CONTEXT * pfc, char * variableName )
{
    BOOL  fRet          = FALSE;
    CHAR *pszBuf        = NULL;
    int cbBuf           = 0;
    IirfVdirConfig *cfg = GetVdirConfigFromFilterContext(pfc);

    LogMessage(cfg, 5, "GetServerVariable: getting '%s'", variableName);

    // Handle the case where the filter logic is not hosted in an ISAPI,
    // in other words, it is in TestDriver.exe.
    if (pfc==NULL || pfc->GetServerVariable == NULL) {
        pszBuf = _strdup(variableName);
        cbBuf= Iirf_ConvertSizeTo32bits(strlen(variableName));
    }

    // Handle special variable name(s)
    else if (_stricmp(variableName, "REQUEST_FILENAME")==0) {
        IirfRequestContext *ctx = (IirfRequestContext *) pfc->pFilterContext;
        LogMessage(cfg, 5, "GetServerVariable: special variable name");
        if (ctx!= NULL && (ctx->Magic == IIRF_CONTEXT_MAGIC_NUMBER) && (ctx->PhysicalPath!=NULL)) {
            pszBuf = _strdup(ctx->PhysicalPath);
        }
        else {
            pszBuf = _strdup(variableName);
        }
        cbBuf= Iirf_ConvertSizeTo32bits(strlen(pszBuf));
    }

    else if (_stricmp(variableName, "REQUEST_URI")==0) {
        IirfRequestContext *ctx = (IirfRequestContext *) pfc->pFilterContext;
        if (ctx!= NULL && (ctx->Magic == IIRF_CONTEXT_MAGIC_NUMBER)) {
            pszBuf = _strdup(ctx->RequestUri);
        }
        else {
            pszBuf = _strdup(variableName);
        }
        cbBuf = Iirf_ConvertSizeTo32bits(strlen(pszBuf));
    }

    // Don't use pfc->GetServerVariable for URL, because it lacks the query
    // string.  Also, updates made to that header/variable via
    // pfc->SetHeader() are not available during intermediate rewrite
    // iterations.
    else if (_stricmp(variableName, "URL")==0 || _stricmp(variableName, "method")==0) {
        pszBuf = _strdup(GetStashedHeader_AutoFree(pfc, variableName));
        LogMessage(cfg,5,"GetStashedHeader(%s): '%s'", variableName, pszBuf);
        cbBuf = Iirf_ConvertSizeTo32bits(strlen(pszBuf));
    }

    // workitem 30399 - TIME pseudo variables
    else if (GetTimeVariable(variableName, &pszBuf)) {
        cbBuf = Iirf_ConvertSizeTo32bits(strlen(pszBuf));
    }

    else {
        cbBuf = SERVER_VAR_BUFFER_SIZE_DEFAULT;
        pszBuf = (CHAR *) malloc(cbBuf);
        pszBuf[0]='\0';
        fRet = pfc->GetServerVariable( pfc, variableName, pszBuf, &cbBuf );

        if ( fRet == FALSE ) {
            if ( GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                // The buffer is not large enough.
                LogMessage(cfg,5,"GetServerVariable: the initial buffer is not large enough.");

                // is the required size within the configured limit?
                if (cbBuf > gFilterConfig->MaxFieldLength ) {
                    LogMessage(cfg, 1, "** ERROR: the required buffer size (%d) exceeds the limit (%d)",
                               cbBuf, gFilterConfig->MaxFieldLength );
                    SetLastError( ERROR_BAD_LENGTH );
                    goto GSV2_Finished;
                }

                // Reallocate the buffer.
                free(pszBuf);
                pszBuf = (CHAR *) malloc(++cbBuf);
                if ( pszBuf == NULL ) {
                    SetLastError( ERROR_NOT_ENOUGH_MEMORY );
                    goto GSV2_Finished;
                }

                // workitem 15113
                pszBuf[0]='\0';
                fRet = pfc->GetServerVariable( pfc, variableName, pszBuf, &cbBuf );
                if ( fRet == FALSE ) {
                    int e = GetLastError();
                    char eMsg[256];
                    Iirf_GenErrorMessage(e, eMsg, 256);
                    LogMessage(cfg, 1,"GetServerVariable failed on 2nd pass. %s", eMsg);
                    pszBuf[0]='\0';
                    //strcpy_s(pszBuf,cbBuf,variableName);
                }
            }
            else if ( GetLastError() == ERROR_INVALID_INDEX ) {
                LogMessage(cfg, 2, "GetServerVariable: cannot find that variable");
                pszBuf[0]='\0';
                //strcpy_s(pszBuf,SERVER_VAR_BUFFER_SIZE_DEFAULT,variableName);
            }
            else {
                int e = GetLastError();
                char eMsg[256];
                Iirf_GenErrorMessage(e, eMsg, 256);
                LogMessage(cfg, 1,"GetServerVariable failed. %s", eMsg);
                pszBuf[0]='\0';
                //strcpy_s(pszBuf,SERVER_VAR_BUFFER_SIZE_DEFAULT,variableName);
            }
        }
    }

GSV2_Finished:

    // This stanza is for logging only.
    LogMessage(cfg, 5,"GetServerVariable: %d bytes", cbBuf);
    LogMessage(cfg, 5,"GetServerVariable: result '%s'", pszBuf);

    //
    // At this point, pszBuf points to the variable value and
    // cbBuf is the strlen(), or in case of the default being large
    // enough, it is the size of the buffer (128 bytes).
    //

    return pszBuf;
}





char * GetServerVariable_AutoFree(HTTP_FILTER_CONTEXT * pfc,
                                  char * variableName )
{
    BOOL  fRet          = FALSE;
    int   dwSize        = 128; // default size
    CHAR *pszBuf ;
    IirfVdirConfig *cfg = GetVdirConfigFromFilterContext(pfc);

    TRACE("GetServerVariable_AutoFree");
    LogMessage(cfg, 5,"GetServerVariable_AutoFree: getting '%s'", variableName);

    // Handle the case where the filter logic is not hosted in an ISAPI,
    // in other words, it is in TestDriver.exe.
    if (pfc==NULL || pfc->GetServerVariable == NULL) {
        LogMessage(cfg, 5,"GetServerVariable_AutoFree: no PFC, returning '%s'", variableName);
        return variableName;
    }

    // Handle special variable name(s).

    // URL, method, and version are exceptions, because by default in IIS6+,
    // GetServerVariable("*") with any of those, returns the original,
    // unchanged values.  Likewise with GetHeader. The result is that, if a
    // RewriteCond tests any of those server variables, the value appears not
    // to have been updated. Therefore, we need to stash the value when
    // updating any of those things in a RewriteHeader, and then retrieve from
    // the stash as necessary.  Actually I'm not going to allow updates to the
    // version header, because that shouldn't be changed.
    //

    if (_stricmp(variableName, "URL")==0 ||
        _stricmp(variableName, "METHOD")==0) {
        LogMessage(cfg, 5,"GetServerVariable_AutoFree: delegating to GetStashedHeader");
        return Iirf_IsapiStrdup(pfc,GetStashedHeader_AutoFree(pfc, variableName));
    }

    if (strcmp(variableName, "REQUEST_FILENAME")==0) {
        IirfRequestContext *ctx = (IirfRequestContext *) pfc->pFilterContext;
        return ctx->PhysicalPath;
    }

    if (strcmp(variableName, "REQUEST_URI")==0) {
        IirfRequestContext *ctx = (IirfRequestContext *) pfc->pFilterContext;
        return ctx->RequestUri;
    }

    pszBuf = (char *) pfc->AllocMem(pfc, dwSize, 0);

    if ( pszBuf == NULL ) {
        SetLastError( ERROR_NOT_ENOUGH_MEMORY );
        goto GSV_Finished;
    }

    // workitem 15113
    pszBuf[0]='\0';

    TRACE("GetServerVariable_AutoFree: getting variable (dwsize=%d)", dwSize);

    fRet = pfc->GetServerVariable( pfc, variableName, pszBuf, &dwSize );
    if (fRet==FALSE) {
        if (GetLastError() == ERROR_INVALID_INDEX) {
            // unknown server variable - return an empty non-null string.
            pszBuf[0]= '\0';
            fRet= TRUE;
            goto GSV_Finished;
        }
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            pszBuf= NULL;
            goto GSV_Finished;
        }

        // fail if the required buffer size exceeds the configured limit.
        if (dwSize > gFilterConfig->MaxFieldLength ) {
            LogMessage(cfg, 1, "** ERROR: the required buffer size (%d) exceeds the limit (%d)",
                       dwSize, gFilterConfig->MaxFieldLength );
            SetLastError( ERROR_BAD_LENGTH );
            goto GSV_Finished;
        }

        // AllocMem allocates memory that is scoped to the HTTP request;
        // The memory is automatically free'd in completion of the request.
        pszBuf= (char *) pfc->AllocMem(pfc, dwSize, 0);
        if ( pszBuf == NULL ) {
            SetLastError( ERROR_NOT_ENOUGH_MEMORY );
            goto GSV_Finished;
        }

        // workitem 15113
        pszBuf[0]='\0';
        fRet = pfc->GetServerVariable(pfc, variableName, pszBuf, &dwSize );
        if ( fRet == FALSE )
            goto GSV_Finished;
    }

GSV_Finished:
    if ( fRet == FALSE ) {
        int e = GetLastError();
        char eMsg[256];
        Iirf_GenErrorMessage(e, eMsg, 256);
        LogMessage(cfg, 5,"GetServerVariable_AutoFree - failed (error %d, %s)",
                   e, eMsg);
    }

    LogMessage(cfg, 5,"GetServerVariable_AutoFree: %d bytes", dwSize);
    LogMessage(cfg, 5,"GetServerVariable_AutoFree: result '%s'", pszBuf);

    //
    // At this point, pszBuf points to the variable value (if any) and
    // dwSize indicates size of buffer, including terminating NULL.
    //

    return pszBuf;
}




// allocator
typedef void * (*IirfAllocator)(HTTP_FILTER_CONTEXT * pfc, int sizeInBytesToAllocate) ;

char * _GetHeaderImpl(HTTP_FILTER_CONTEXT * pfc,
                      char * variableName,
                      IirfAllocator allocator,
                      const char * label )
{
    BOOL   fRet = FALSE;
    DWORD  dwSize = 128; // default size
    CHAR *pszBuf ;
    IirfVdirConfig *cfg = GetVdirConfigFromFilterContext(pfc);
    IirfRequestContext *ctx = NULL;

    LogMessage(cfg, 5,"GetHeader%s: getting '%s'", label, variableName);

    if (pfc==NULL) {
        // happens in a testing context
        LogMessage(cfg, 5,"GetHeader%s: no PFC, returning '%s'",
                   label, variableName);
        return variableName;
    }
    pszBuf = (char *) allocator(pfc, dwSize);
    ctx = (IirfRequestContext*) pfc->pFilterContext;

    fRet= ctx->AuthCompleteInfo->GetHeader(pfc, variableName, pszBuf, &dwSize);
    if (fRet==FALSE) {
        if (GetLastError() == ERROR_INVALID_INDEX) {
            // unknown header - return an empty non-null string.
            pszBuf[0]= '\0';
            fRet= TRUE;
            goto GHI_Finished;
        }
        else if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            pszBuf= NULL;
            goto GHI_Finished;
        }
        // AllocMem does request-scoped memory allocation, with auto free.
        pszBuf= (char *) allocator(pfc, dwSize);
        if ( pszBuf == NULL ) {
            SetLastError( ERROR_NOT_ENOUGH_MEMORY );
            goto GHI_Finished;
        }
        fRet= ctx->AuthCompleteInfo->GetHeader(pfc, variableName, pszBuf, &dwSize);
        if ( fRet == FALSE )
            goto GHI_Finished;
    }

GHI_Finished:
    if ( fRet == FALSE ) {
        int e = GetLastError();
        char eMsg[256];
        Iirf_GenErrorMessage(e, eMsg, 256);
        LogMessage(cfg, 5,"GetHeader_%s failed (error %d, %s)", label, e, eMsg);
    }

    LogMessage(cfg, 5, "GetHeader%s: %d bytes   ptr:0x%08X", label, dwSize, pszBuf);
    LogMessage(cfg, 4, "GetHeader%s: '%s' = '%s'", label, variableName, pszBuf);

    return pszBuf;
}



void * IirfAllocator_AllocMem(HTTP_FILTER_CONTEXT * pfc, int sizeInBytesToAllocate)
{
    return pfc->AllocMem(pfc, sizeInBytesToAllocate, 0);
}


void * IirfAllocator_Malloc(HTTP_FILTER_CONTEXT * pfc, int sizeInBytesToAllocate)
{
    return malloc(sizeInBytesToAllocate);
}


char * GetHeader(HTTP_FILTER_CONTEXT * pfc, char * variableName )
{
    return _GetHeaderImpl(pfc,
                          variableName,
                          IirfAllocator_Malloc,
                          "");
}


char * GetHeader_AutoFree(HTTP_FILTER_CONTEXT * pfc, char * variableName )
{
    return _GetHeaderImpl(pfc,
                          variableName,
                          IirfAllocator_AllocMem,
                          "_AutoFree");
}





static HINSTANCE g_hInstance = NULL;

HINSTANCE __stdcall AfxGetResourceHandle()
{
    return g_hInstance;
}


// See debugger.h
//
// This is to provide an un-suppressible DebugBreak().
//
void __stdcall PreDebugBreakAnyway()
{
    if (IsDebuggerPresent()) {
        // We're running under the debugger.
        // There's no need to call the inner DebugBreak
        // placed in the two __try/__catch blocks below,
        // because the outer DebugBreak will
        // force a first-chance exception handled in the debugger.
        return;
    }

    __try {
        __try {
            DebugBreak();
        }
        __except ( UnhandledExceptionFilter(GetExceptionInformation()) ) {
            // You can place the ExitProcess here to emulate work
            // of the __except block from BaseStartProcess
            // ExitProcess( 0 );
        }
    }
    __except ( EXCEPTION_EXECUTE_HANDLER ) {
        // We'll get here if the user has pushed Cancel (Debug).
        // The debugger is already attached to our process.
        // Return to let the outer DebugBreak be called.
    }
}



/*
 * Set gIirfVersion string to a meaningful string.
 *
 * something like:
 *
 * Ionic ISAPI Rewriting Filter (IIRF) 2.0.1.1003 DEBUG
 *
 */
void SetFilterVersionInfo()
{
    if (gIirfVersion == NULL) {
        ULONGLONG fileVersion = 0;
        VS_FIXEDFILEINFO *fInfo = NULL;
        DWORD dwHandle;
        // get the version number of the DLL
        DWORD dwSize = GetFileVersionInfoSizeA(gFilterConfig->DllLocation, &dwHandle);
        if (dwSize > 0) {
            LPVOID vData = malloc(dwSize);
            if (vData != NULL) {
                if (GetFileVersionInfoA(gFilterConfig->DllLocation, dwHandle, dwSize, vData) != 0) {
                    UINT len;
                    TCHAR szSubBlock[] = _T("\\");
                    if (VerQueryValue(vData, szSubBlock, (LPVOID*) &fInfo, &len) == 0)
                        fInfo = NULL;
                    else {
                        fileVersion = ((ULONGLONG)fInfo->dwFileVersionLS) + ((ULONGLONG)fInfo->dwFileVersionMS << 32);
                    }
                }
                free(vData);
            }
        }

        if (fileVersion == 0) {
            gIirfVersion = Iirf_AllocAndSprintf(NULL,
                                                "%s 0.0.0.0 %s %s",
                                                IIRF_FILTER_NAME,
                                                cpuFlavor,
                                                buildFlavor);
        }
        else {
            DWORD v4 = (DWORD) fileVersion & 0xFFFF;
            DWORD v3 = (DWORD) (fileVersion>>16) & 0xFFFF;
            DWORD v2 = (DWORD) (fileVersion>>32) & 0xFFFF;
            DWORD v1 = (DWORD) (fileVersion>>48) & 0xFFFF;
            const char *shortFormat;
            gIirfVersion = Iirf_AllocAndSprintf(NULL,
                                                "%s %d.%d.%d.%d %s %s",
                                                IIRF_FILTER_NAME,
                                                v1, v2, v3, v4,
                                                cpuFlavor,
                                                buildFlavor);

            // now the short version string
            shortFormat = (strcmp(buildFlavor,"RELEASE")==0)
                ? "IIRF v%d.%d"
                : "IIRF v%d.%dD";

            gIirfShortVersion = Iirf_AllocAndSprintf(NULL, shortFormat, v1, v2);
        }
    }
}




BOOL WINAPI DllMain(HINSTANCE hInst, ULONG ulReason, LPVOID lpReserved)
{
    boolean retVal= FALSE;

    //DebugBreakAnyway();

    TRACE("DllMain: ulReason = 0x%08lx", ulReason);

    switch( ulReason ) {

        case DLL_PROCESS_ATTACH:
            // on process attach we can initialize the state of the filter.

            if ( ! gFilterInitialized ) {
                char ProgramFname[_MAX_PATH];
                char Extension[_MAX_PATH];
                char ProgramName[_MAX_PATH];
                char drive[_MAX_DRIVE];
                char dir[_MAX_DIR];
                char *MyFullProgramName= NULL;
                static const char *TestProgramName1= "TestDriver.exe";
                static const char *TestProgramName2= "TestParse.exe";
                static const char *TestProgramName3= "IirfVersion.exe";
                static const char *VersionProgramName= "IirfVersion.exe";

                InitializeCriticalSection(&gcsFilterConfig);
                InitializeCriticalSection(&gcsLogFileList);
                InitializeCriticalSection(&gcsVdirConfig);

                EnterCriticalSection(&gcsFilterConfig);

                gFilterConfig= Iirf_NewServerConfig();

                CacheLogMessage(1, "DLL_PROCESS_ATTACH");
                CacheLogMessage(1, "Process ID: %d", GetCurrentProcessId() );

                InitializeUrlDecoder();

                // http://www.codeplex.com/IIRF/WorkItem/View.aspx?WorkItemId=17002
                // set handle for *_s secure string handling - invalid params.
                // see http://msdn.microsoft.com/en-us/library/a9yf33zb.aspx
                _set_invalid_parameter_handler( IirfInvalidParameterHandler );

                // Disable the message box for assertions. (like "buffer too small")
                _CrtSetReportMode(_CRT_ASSERT, 0);

                if (GetModuleFileName(hInst, gFilterConfig->DllLocation, sizeof(gFilterConfig->DllLocation))) {
                    _splitpath_s(gFilterConfig->DllLocation, drive, _MAX_DRIVE, dir, _MAX_DIR, gFilterConfig->DllModuleFname, _MAX_FNAME, NULL, 0);
                    _makepath_s(gFilterConfig->IniFileName, _MAX_PATH, drive, dir, "IirfGlobal", ".ini");
                    TRACE("global ini file: '%s'", gFilterConfig->IniFileName);
                    retVal= TRUE;
                }
                else
                    CacheLogMessage(1, "Cannot get module name??");

                SetFilterVersionInfo();

                Iirf_ReadServerConfig(gFilterConfig);

                // Here we need to check whether the DLL is running in testdriver.EXE, and not within the context
                // of a webserver (eg, inetinfo.exe on IIS5 or w3wp.exe on IIS6.
                // _pgmptr is a global variable that stores the full path of the executable image name, but it is
                // deprecated in VC8, so we use the _get_pgmptr() routine instead.
                _get_pgmptr(&MyFullProgramName);
                _splitpath_s(MyFullProgramName, drive, _MAX_DRIVE, dir, _MAX_DIR, ProgramFname, _MAX_FNAME, Extension, _MAX_PATH);
                sprintf_s(ProgramName, _MAX_PATH, "%s%s", ProgramFname, Extension);

                if (_strnicmp(ProgramName, VersionProgramName, strlen(VersionProgramName))==0) {
                    // do nothing!
                    gFilterConfig->Testing= TRUE;
                    retVal= TRUE;
                }

                else if ((_strnicmp(ProgramName, TestProgramName1, strlen(TestProgramName1))==0) ||
                         (_strnicmp(ProgramName, TestProgramName2, strlen(TestProgramName2))==0) ||
                         (_strnicmp(ProgramName, TestProgramName3, strlen(TestProgramName3))==0)) {
                    gFilterConfig->Testing= TRUE;
                    retVal= TRUE;
                }

                CacheLogMessage(1, "DLL_PROCESS_ATTACH - complete");
                gFilterInitialized= TRUE;
                LeaveCriticalSection(&gcsFilterConfig);
            }
            break;

        case DLL_THREAD_DETACH:
            CacheLogMessage(5, "DLL_THREAD_DETACH");
            break;

        case DLL_PROCESS_DETACH:
            if (gAlreadyCleanedUp) break;
            DeleteCriticalSection(&gcsFilterConfig);
            DeleteCriticalSection(&gcsLogFileList);
            DeleteCriticalSection(&gcsVdirConfig);
            if (gIirfVersion) free(gIirfVersion);

            if (gIirfStartupTime) free(gIirfStartupTime);
            gAlreadyCleanedUp= TRUE;
            break;

    }
    return retVal;
}
