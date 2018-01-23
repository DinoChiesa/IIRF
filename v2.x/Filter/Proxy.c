//#define IIRF_DIAG_PROXY_OPS 1

/*

  Proxy.c

  part of Ionic's Isapi Rewrite Filter [IIRF]

  IIRF is an add-on to IIS that can rewrite URLs.
  Inspired by Apache's mod_rewrite .
  Implemented in C, does not use MFC.

  Copyright (c) Dino Chiesa and Microsoft Corporation, 2005-2009.
  All rights reserved.

  ==================================================================

  License
  ---------------------------------

  IIRF and its documentation is distributed under
  the Microsoft Permissive License.  See the attached License.txt file
  that accompanies the source distribution.

*/



#include <WTypes.h>    // for DWORD, etc
#include <HttpFilt.h>  // HTTP_FILTER_CONTEXT, etc
#include <WinHttp.h>   // WinHttp*

#include <stdio.h>
#include <time.h>      // for time() (diagnostic use only)
#include <share.h>     // for _SH_DENYNO

#include "Iirf.h"

#include "pcre.h"


// externs
extern IirfVdirConfig * GetVdirConfigFromFilterContext(HTTP_FILTER_CONTEXT * pfc);          // IirfConfig.c
extern char * GetServerVariable_AutoFree( PHTTP_FILTER_CONTEXT pfc, char * VariableName );  // Rewriter.c
extern char * gIirfShortVersion;                                                            // Rewriter.c
extern char * GetServerVariable(PHTTP_FILTER_CONTEXT pfc, char * VariableName );            // Rewriter.c
extern void LogMessage( IirfVdirConfig * cfg, int MsgLevel, const char * format, ... );     // IirfLogging.c
extern char * Iirf_AllocAndSprintf( HTTP_FILTER_CONTEXT * pfc, const char * format, ... );  // Utils.c
extern WCHAR ** Iirf_wTokenizeAccept (IirfVdirConfig * cfg, const CHAR* string);            // Utils.c
extern LPSTR Iirf_WideCharToAscii(LPCWSTR w);                                               // Utils.c
extern WCHAR * Iirf_AsciiToWideChar(LPCSTR p);                                              // Utils.c
extern void Iirf_ReleaseArrayWchar(  IirfVdirConfig * cfg,  WCHAR** pw);                    // Utils.c


extern CRITICAL_SECTION  gcsFilterConfig;


pcre *chunkedEncodingRe = NULL;




IirfRequestHeader * GetHeaderValueByName(IirfRequestHeader * rh, char *name)
{
    if (rh == NULL) return NULL;
    do
    {
        if (strcmp(rh->S[0], name)==0) return rh;
        rh= rh->Next;
    } while (rh != NULL);
    return NULL;
}



/* IirfProxy_ParseAllRaw
 *
 * Purpose:
 *
 *     Parses the ALL_RAW string and returns a linked list of IirfRequestHeader
 *     structs. Each node in the list corresponds to a single request header.
 *     Later this list is used to determine which headers to send in the outgoing
 *     (proxied) request.
 *
 * Arguments:
 *
 *     The ALL_RAW string.
 *
 * Returns:
 *
 *     IirfRequestHeader *. Caller must free the list via
 *     IirfProxy_FreeIirfRequestHeaders
 *
 */
IirfRequestHeader* IirfProxy_ParseAllRaw(IirfVdirConfig * cfg, char * allRaw)
{
    IirfRequestHeader* root = NULL;
    IirfRequestHeader* prev = NULL;
    IirfRequestHeader* current;
    char * subject = allRaw;
    char * t ;
    char * ctx1= NULL;
    char * px;
    int cycle = 0;

    LogMessage(cfg, 4, "ParseAllRaw: %s", allRaw);

    px= strtok_s(subject, "\r\n", &ctx1);

    while (px!=NULL) {
        t = strchr(px, ':');
        if (t>0) {
            current = (IirfRequestHeader*) malloc(sizeof(IirfRequestHeader));
            current->Next = NULL;
            *t = '\0';
            current->S[0] = _strdup(px);
            current->S[1] = _strdup(t+2);
            *t = ':'; // restore
            LogMessage(cfg, 4, "ParseAllRaw: hdr %s: %s", current->S[0],current->S[1]);
            if (root == NULL) {
                prev = root = current;
            }
            else {
                prev->Next = current;
                prev = current;
            }
        }
        else {
            LogMessage(cfg, 4, "ParseAllRaw: no colon (%s) cycle(%d)", px, cycle);
        }
        cycle++;
        px = strtok_s(NULL, "\r\n", &ctx1);
    }

    LogMessage(cfg, 3, "ParseAllRaw: found %d headers", cycle);

    return root;
}




/* IirfProxy_GetHeaderString
 *
 * Purpose:
 *     Allocates and returns the header string, including the terminating
 *     \r\n sequence for the given IirfRequestHeader.  This is basically
 *     a glorified ToString() function.
 *
 * Arguments:
 *
 *     rh - IirfRequestHeader.  Obtained from parsing the ALL_RAW SV via
 *          IirfProxy_ParseAllRaw.
 *
 * Returns:
 *
 *     The allocated and formatted string, null terminated. Includes a \r\n
 *     pair before the terminator. Caller must free.
 *
 */
char * IirfProxy_GetHeaderString(IirfRequestHeader * rh)
{
    char * result = NULL;
    size_t len = 0;
    if (rh == NULL) return _strdup("");
    len = strlen(rh->S[0]) + 2 + strlen(rh->S[1]) + 3;
    result = malloc(len);
    strcpy_s(result, len, rh->S[0]);
    strcat_s(result, len, ": ");
    strcat_s(result, len, rh->S[1]);
    strcat_s(result, len, "\r\n");
    return result;
}





/* IirfProxy_ConstructPprHeader
 *
 * Purpose:
 *     Generates a header, Substituting the URI value of the header
 *     using the ProxyPassReverse structure chain in the vdir config.
 *     This is intended to work only with Location and Content-Location
 *     headers.
 *
 * Arguments:
 *
 *     origHdr - const char *.
 *          the original header value from the incoming response.
 *
 *     ppr - const ProxyPassReverse *.
 *          chain of ppr substitution structs from config.
 *
 *     serverName - const char *.
 *          name used on the original incoming request, which
 *          resulted in an outgoing proxied request.
 *
 *     port - const char *.
 *          port used on the original request.
 *
 *     https - const char *.
 *          on/off value from the original request.
 *
 * Returns:
 *
 *     The allocated and formatted header string, null terminated. Does
 *     not include a \r\n pair before the terminator. Caller must free.
 *
 */
char * IirfProxy_ConstructPprHeader(IirfVdirConfig * cfg,
                                    const char * origHdr,
                                    const ProxyPassReverse * ppr,
                                    const char * serverName,
                                    const char * port,
                                    const char * https )
{
    // parse the header string
    char * localOrigHdr= _strdup(origHdr);
    char * t = strchr(localOrigHdr, ':');
    char * hdrName = localOrigHdr;
    char * hdrValue = t+2;
    *t = '\0'; // terminate at the colon

    while (ppr!= NULL) {
        LogMessage(cfg, 5, "ConstructPprHeader: compare loc(%s) pprurl(%s) len(%d)",
                   hdrValue, ppr->url, ppr->L1);

        if (strncmp(ppr->url, hdrValue, ppr->L1) == 0) {
            // The value in the recd hdr is the same as that specd in a PPR directive.
            char * scheme = (_strnicmp(https,"on", strlen(https)) ? "http" : "https");
            char * result = NULL;

            LogMessage(cfg, 5, "ConstructPprHeader: match");

            if (((strcmp(port,"80")==0) && (strcmp(scheme,"http")==0)) ||
                ((strcmp(port,"443")==0) && (strcmp(scheme,"https")==0))) {
                // The orig request used the default port; no need to specify it in the new header.
                static const char * fmtString1=  "%s: %s://%s%s%s%s";
                result = Iirf_AllocAndSprintf(NULL, fmtString1, hdrName, scheme, serverName,
                                              (cfg->RewriteBase)?cfg->RewriteBase:"",
                                              ppr->path, hdrValue + ppr->L1);
            }
            else {
                // The orig request used a non-standard port; must explicitly specify it in the new header.
                static const char * fmtString1=  "%s: %s://%s:%s%s%s%s";
                result = Iirf_AllocAndSprintf(NULL, fmtString1, hdrName, scheme, serverName, port,
                                              (cfg->RewriteBase)?cfg->RewriteBase:"",
                                              ppr->path, hdrValue + ppr->L1);
            }

            LogMessage(cfg, 5, "ConstructPprHeader: default port. hdrName(%s) scheme(%s) s(%s) L1(%d) port(%s) path(%s) trim(%s)",
                       hdrName, scheme, serverName, ppr->L1, port, ppr->path, (hdrValue + ppr->L1));

            free(localOrigHdr);
            return result;
        }
        else
            LogMessage(cfg, 5, "ConstructPprHeader: no match");

        ppr = ppr->next;
    }

    free(localOrigHdr);
    return _strdup(origHdr);
}



/* IirfProxy_FreeIirfRequestHeaders
 *
 * Purpose:
 *     Frees the IirfRequestHeader linked list, obtained from
 *     IirfProxy_ParseAllRaw.
 *
 * Arguments:
 *
 *     IirfRequestHeader *.  Obtained from parsing the ALL_RAW SV via
 *          IirfProxy_ParseAllRaw.
 *
 * Returns:
 *
 *     -nothing-
 *
 */
void IirfProxy_FreeIirfRequestHeaders(IirfRequestHeader * rh)
{
    if (rh == NULL) return;
    free(rh->S[0]);
    free(rh->S[1]);
    IirfProxy_FreeIirfRequestHeaders(rh->Next);
    free(rh);
}



/* IirfProxy_GenProxyRequestHeadersString
 *
 * Purpose:
 *
 *     Allocates and fills the string that contains all headers
 *     appropriate for the outgoing (proxied) request. Most of the
 *     values of the outbound headers are the same as the corresponding
 *     values for the incoming headers, but some headers are
 *     different. This fn takes in the input headers and produces the
 *     appropriate set of output headers.
 *
 *     A summary of actions on request headers and server variables across the proxy:
 *
 *     incoming          type  outgoing
 *     -----------------------------------------------------------------------
 *     Host:             HDR   put into X-Forwarded-For:, if not set already in the
 *                             incoming request
 *     (all others)      HDR   pass through
 *     newHost           arg   put into Host: header.
 *     serverName        arg   put into X-Forwarded-Server:
 *     localAddr         arg   inject RFC2616-compliant Via: header (see sec 14.45)
 *     remoteAddr        arg   append into X-Forwarded-For:
 *
 * Arguments:
 *
 *     rhRoot (IirfRequestHeader *)
 *            The list of raw headers for the incoming request, obtained from
 *            parsing the ALL_RAW server variable with IirfProxy_ParseAllRaw.
 *
 *     newHost (const char *)
 *            The new HOST for the outbound (proxied) request.  This may
 *            or may not be the hostname specified in the outbound
 *            (proxied) URL. See ProxyPreserveHost.
 *
 *     serverName (const char *)
 *            Name of the server acting as proxy, the IIRF server.  This
 *            is obtained from SERVER_NAME Server variable. Used to produce
 *            the X-Forwarded-Server: header.
 *
 *     localAddr (char *)
 *            IP addr of IIRF client. Used to produce the Via: header.
 *
 *     remoteAddr (char *)
 *            IP addr of requesting client. Used to produce the
 *            X-Forwarded-For: header.
 *
 *     dwTotalSize (DWORD)
 *            A DWORD that holds the ostensible total size of the data
 *            to be transmitted across the proxy. The value is used
 *            solely for validation. If it is zero, the Content-Length
 *            header must not be present. (GET). If this is non-zero,
 *            the Content-Length header must be present (POST/PUT), and
 *            must agree. If this check doesn't pass, the fn logs an
 *            error and continues. Eventually the end agent will
 *            confront the error and deal with it.
 *
 *            I had considered to make this a DWORD *, and then if these
 *            constraints don't hold, then set the DWORD to -1, on exit,
 *            to signal an HTTP protocol violation.  But the caller
 *            doesn't know what to do with the protocol error.  Given that,
 *            this fn kicks such an error down the line.
 *
 * Returns:
 *
 *     the entire header string.  Caller must free.
 *
 */
char * IirfProxy_GenProxyRequestHeadersString(IirfVdirConfig *cfg,
                                              IirfRequestHeader *rhRoot,
                                              const char *newHost,
                                              const char *serverName,
                                              char *localAddr,
                                              char *remoteAddr,
                                              DWORD dwTotalSize)
{
    int pass;
    int n;
    char **s;
    char * result = NULL;
    boolean xffFound = FALSE;
    boolean viaFound = FALSE;
    DWORD contentLength = 0xFFFFFFFF;
    IirfRequestHeader *rh = rhRoot;

    LogMessage(cfg, 3, "GenProxyRequestHeadersString: rh(0x%08X) nh(%s) sn(%s) la(%s) ra(%s) ts(%d)",
               rh, newHost, serverName, localAddr, remoteAddr, dwTotalSize);

    if (rh == NULL) return _strdup("");

    // two passes: 1st to count space and allocate, 2nd to copy.
    for (pass=0; pass < 2;  pass++) {
        rh = rhRoot;
        n = 0;
        do {
            if (pass!=0) {
                if (_stricmp(rh->S[0], "Host")==0) {
                    s[n] = Iirf_AllocAndSprintf(NULL, "X-Forwarded-Host: %s\r\n", rh->S[1]);
                }
                else if (_stricmp(rh->S[0], "X-Forwarded-For")==0) {
                    xffFound = TRUE;
                    s[n] = Iirf_AllocAndSprintf(NULL, "X-Forwarded-For: %s, %s\r\n", rh->S[1], remoteAddr);
                }
                else if (_stricmp(rh->S[0], "Via")==0) {
                    viaFound = TRUE;
                    // comply with RFC 2616 sec 14.45.
                    s[n] = Iirf_AllocAndSprintf(NULL, "Via: %s, 1.1 %s (%s)\r\n", rh->S[1], localAddr, gIirfShortVersion);
                }
                else if (_stricmp(rh->S[0], "Content-Length")==0) {
                    // will use this to later validate against dwTotalSize
                    contentLength = atoi(rh->S[1]);
                    s[n] = IirfProxy_GetHeaderString(rh);
                }
                else {
                    s[n] = IirfProxy_GetHeaderString(rh);
                }
            }
            n++;
            rh= rh->Next;
        } while (rh != NULL);

        if (pass==0) {
            s = (char**) malloc(n * sizeof (char*));
        }
        else {
            // now generate the complete set of headers in one string
            int j;
            size_t tlen = 0;
            char *via = NULL;

            // sanity check
            if ((contentLength != 0xFFFFFFFF && dwTotalSize!=contentLength) ||
                (contentLength == 0xFFFFFFFF && dwTotalSize!=0)) {
                LogMessage(cfg, 2, "GenProxyRequestHeadersString: protocol error detected: Content-Length(0x%08X) and cbTotalBytes(0x%08X) disagree", contentLength, dwTotalSize);
                //*pdwTotalSize = 0xFFFFFFFFul;
            }

            for (j=0; j < n;  j++)
                tlen += strlen(s[j]);

            tlen += (strlen("Host: ") + 3 + strlen(newHost));
            if (!viaFound) {
                via = Iirf_AllocAndSprintf(NULL, "Via: 1.1 %s (%s)\r\n", localAddr, gIirfShortVersion);
                tlen += strlen(via);
            }

            if (!xffFound)
                tlen += (strlen("X-Forwarded-For: ") + 3 + strlen(remoteAddr));

            tlen += (strlen("X-Forwarded-Server: ") + 3 + strlen(serverName));

            result = malloc(++tlen);
            result[0] = '\0';

            strcat_s(result, tlen, "Host: ");
            strcat_s(result, tlen, newHost);
            strcat_s(result, tlen, "\r\n");

            if (!viaFound) {
                strcat_s(result, tlen, via);
                free(via);
            }

            strcat_s(result, tlen, "X-Forwarded-Server: ");
            strcat_s(result, tlen, serverName);
            strcat_s(result, tlen, "\r\n");
            if (!xffFound) {
                strcat_s(result, tlen, "X-Forwarded-For: ");
                strcat_s(result, tlen, remoteAddr);
                strcat_s(result, tlen, "\r\n");
            }

            for (j=0; j < n;  j++) {
                strcat_s(result, tlen, s[j]);
                free(s[j]);
            }

            // diagnostics only
            if (cfg->LogLevel>=5) {
                char * ctx= NULL;
                // use a copy to avoid modifying the result
                char * tstr= _strdup(result);
                char * px = strtok_s(tstr, "\r\n", &ctx);
                while (px!=NULL) {
                    LogMessage(cfg, 4, "GenProxyRequestHeadersString: header %s", px);
                    px = strtok_s(NULL, "\r\n", &ctx);
                }
                free(tstr);
            }
        }
    }

    return result;
}




/* IirfProxy_ProcessResponseHeaders
 *
 * Purpose:
 *
 *     Generates a response header string to return to the original client,
 *     given a header string received from the proxied server.  The headers
 *     returned to the client depend on the headers received from the proxied
 *     resource, but are different. Some are kept unchanged, some are
 *     modified, some new headers are added, some received headers are
 *     dropped.  This fn takes in the first set of headers and produces the
 *     appropriate set of manipulated headers.
 *
 *     Summary of actions on response headers across the proxy:
 *
 *     rec'd header      action
 *     -----------------------------------------------------------------------
 *     Server            exclude
 *     X-Powered-By      exclude
 *     Via               modified to append IIRF's host
 *     Location,
 *     Content-Location  Apply substitution according to ProxyPassReverse directives.
 *                       These are often recd in a 3xx (Redirect) or a 201 (Created)
 *                       response.
 *     (all others)      keep
 *
 * Arguments:
 *
 *     hdrString (char *)
 *         an allocated pointer, it contains the raw response headers.
 *         Successive headers are separated by a \r\n pair.  This fn
 *         frees this pointer when it is finished.
 *
 *     localAddr (char *)
 *         IP addr of requesting client. Used to produce Via.
 *
 *     statusString (char *)
 *         a ptr to hold the HTTP status message. Caller must alloc.
 *         This function fills it.
 *
 *     serverName, port, https (char *)
 *         three ptrs to hold the serverName, port, and https setting for the
 *         original received request. These are used for ProxyPassReverse
 *         substitutions.
 *
 *
 */
char * IirfProxy_ProcessResponseHeaders(IirfVdirConfig * cfg,
                                        char * hdrString,
                                        char * localAddr,
                                        char * statusString,
                                        const char * serverName,
                                        const char * port,
                                        const char * https)
{
    int pass;
    size_t sz= 0;
    char *newHeaderString = NULL;
    char *hdrVia = Iirf_AllocAndSprintf(NULL, "1.1 %s (%s)",
                                        localAddr, gIirfShortVersion);

    // Two passes: the first to count space and allocate, the second to
    // actually do the work.
    for (pass=0; pass < 2; pass++) {
        char * localHdrString = (pass==0) ? _strdup(hdrString) : hdrString;
        char * strtokContext= NULL;
        // split header by \r\n
        char * p = strtok_s(localHdrString, "\r\n", &strtokContext);
        boolean foundVia = FALSE;

        while (p!=NULL) {
            // Sometimes we get the status code in the raw headers.
            // We need to trim that out.
            if (_strnicmp(p,"HTTP/1.", 7)==0) {
                if (pass == 1) {
                    // grab just the the status code from the response
                    char *s= strchr(p, ' ');
                    if (s!= NULL) {
                        char t = '\0';
                        s++; // advance past the space
                        printf("strlen(s)=%d\n", strlen(s));
                        if (strlen(s) >= 32) {
                            t= s[31];
                            s[31]='\0';
                        }
                        strcpy_s(statusString, 32, s);
                        if (t!='\0') s[31]=t;
                    }
                }
            }
            else if ( (_strnicmp(p,"Server: ", 8)==0) ||
                      (_strnicmp(p,"X-Powered-By: ", 14)==0)) {
                // don't copy through
                if (pass==1)
                    LogMessage(cfg, 5, "ProcessResponseHeaders: exclude    '%s'", p);
            }
            else if (_strnicmp(p,"Via: ", 5)==0) {
                // append
                if (pass==0) {
                    sz += strlen(p) + 2 + strlen(hdrVia) + 2;
                }
                else {
                    strcat_s(newHeaderString, sz, p);
                    strcat_s(newHeaderString, sz, ", ");
                    strcat_s(newHeaderString, sz, hdrVia);
                    strcat_s(newHeaderString, sz, "\r\n");
                    foundVia = TRUE;
                    LogMessage(cfg, 5, "ProcessResponseHeaders: append    '%s, %s'", p, hdrVia);
                }
            }
            else if (_strnicmp(p,"Content-Location: ", strlen("Content-Location: "))==0 ||
                     _strnicmp(p,"Location: ", strlen("Location: "))==0) {
                // transform
                char * newHdr = IirfProxy_ConstructPprHeader(cfg, p, cfg->rootPpr, serverName, port, https);
                if (pass==0) {
                    sz += strlen(newHdr) + 2;
                }
                else {
                    // workitem 29164
                    strcat_s(newHeaderString, sz, newHdr);
                    strcat_s(newHeaderString, sz, "\r\n");
                    LogMessage(cfg, 5, "ProcessResponseHeaders: transform old '%s'", p);
                    LogMessage(cfg, 5, "ProcessResponseHeaders:           new '%s'", newHdr);
                }
                free(newHdr);
            }
            else {
                if (pass==0) {
                    sz += strlen(p) + 2;
                }
                else {
                    strcat_s(newHeaderString, sz, p);
                    strcat_s(newHeaderString, sz, "\r\n");
                    LogMessage(cfg, 5, "ProcessResponseHeaders: keep       '%s'", p);
                }
            }

            p= strtok_s(NULL, "\r\n", &strtokContext);
        }

        if (!foundVia) {
            if (pass==0) {
                sz += 5 + strlen(hdrVia) + 2;
            }
            else {
                strcat_s(newHeaderString, sz, "Via: ");
                strcat_s(newHeaderString, sz, hdrVia);
                strcat_s(newHeaderString, sz, "\r\n");
                LogMessage(cfg, 5, "ProcessResponseHeaders: add        'Via: %s'", hdrVia);
            }
        }

        // append the final /r/n to the set of headers
        if (pass==1 && strlen(newHeaderString)>3)
            strcat_s(newHeaderString, sz, "\r\n");

        // allocate
        if (pass==0) {
            if (sz > 3) sz += 2;
            sz+=2;  // need one extra char for the terminator. Let's make it 2.
            LogMessage(cfg, 5, "ProcessResponseHeaders: Allocate  %d", sz);
            newHeaderString = (char *) malloc(sz);
            ZeroMemory(newHeaderString, sz);
        }

        free(localHdrString); // pass 0, free the dupe.  pass 1: free the orig.
    }

    if (cfg->LogLevel>=6) {
        char * ctx= NULL;
        // use a copy to avoid modifying the result
        char * tstr = _strdup(newHeaderString);
        char * px = strtok_s(tstr, "\r\n", &ctx);
        while (px!=NULL) {
            LogMessage(cfg, 6, "ProcessResponseHeaders: header %s", px);
            px = strtok_s(NULL, "\r\n", &ctx);
        }
        free(tstr);
    }

    // see also, this question:
    //    http://stackoverflow.com/questions/1140507
    // for how-to-remove-headers-in-an-isapi-filter.

    free(hdrVia);
    LogMessage(cfg, 4, "ProcessResponseHeaders: all %s", newHeaderString);
    return(newHeaderString);
}




/* IirfProxy_SetRegexForChunkedHeader
 *
 * Purpose:
 *
 *     Set the regex used to scan for the chunked coding in the Transfer-Encoding
 *     header. This is done once per process.
 *
 * Arguments:
 *
 *     cfg - IirfVdirConfig * .  Used for logging only
 *
 * Returns:
 *
 *     -nothing-
 *
 */
VOID IirfProxy_SetRegexForChunkedHeader(IirfVdirConfig * cfg)
{
    // do this only once
    if (chunkedEncodingRe == NULL) {
        static char *pattern = "^(?i)Transfer-Encoding:.*?\\bchunked\\b";
        static int pcreOptions= PCRE_NEWLINE_CRLF | PCRE_MULTILINE;
        const char *error;
        int errorOffset;

        // protect from multi-thread access.
        // Doesn't matter if it gets set twice.
        EnterCriticalSection(&gcsFilterConfig);

        chunkedEncodingRe =
            pcre_compile(pattern,      // the pattern
                         pcreOptions,  // options for the regex
                         &error,       // for any error message
                         &errorOffset, // for error offset
                         NULL);        // use default character tables

        if (chunkedEncodingRe == NULL || error != 0)
            LogMessage(cfg, 1,
                       "SetRegexForChunkedHeader: ERROR: failed to compile regex (p=%s,e=%d)",
                       pattern, error);

        LeaveCriticalSection(&gcsFilterConfig);
    }
}



/*
 * IirfProxy_IsChunkedHeaderPresent
 *
 * Purpose:
 *
 *   Given a string of headers, return true if the "Content-Encoding: chunked"
 *   header is present.  This is a little tricky because Transfer-Encoding can
 *   hold a set of values, including gzip, deflate, compress, and other
 *   extension codings.  So we'll use a regex to scan specifically for the
 *   "chunked" value in the header.
 *
 * Arguments:
 *
 *   cfg - IirfVdirConfig * .  Used for logging only
 *
 *   szHeaders - a string containing all the HTTP Headers.
 *
 *
 * Returns:
 *
 *   TRUE if Content-Encoding: chunked is found.  FALSE otherwise.
 *
 */
BOOL IirfProxy_IsChunkedHeaderPresent(IirfVdirConfig * cfg, const char *szHeaders)
{
#define N_PCRE_OFFSETS 12
    int matchCount;
    int substringOffsets[N_PCRE_OFFSETS];
    int sz = Iirf_ConvertSizeTo32bits(strlen(szHeaders));

    IirfProxy_SetRegexForChunkedHeader(cfg);

    if (chunkedEncodingRe == NULL || chunkedEncodingRe == (pcre*) 0xFFFFFFFF) {
        LogMessage(cfg, 1, "IsChunkedHeaderPresent: ERROR: failed to compile regex");
        chunkedEncodingRe = (pcre*) 0xFFFFFFFF;
        return FALSE;
    }

    matchCount =
        pcre_exec(chunkedEncodingRe,  // the compiled pattern
                  NULL,               // no extra data - we didn't study the pattern
                  szHeaders,          // the subject string
                  sz,                 // the length of the subject
                  0,                  // start at offset 0 in the subject
                  0,                  // default options
                  substringOffsets,   // pre-allocated output vector for substring position info
                  N_PCRE_OFFSETS);    // number of elements allocated in the output vector

    return (matchCount >= 0);

#undef  N_PCRE_OFFSETS
}



/*
 * IirfProxy_GetResponseHeaders
 *
 * Purpose:
 *
 *   Given a HINTERNET (pRequest) for which the caller has already invoked
 *   WinHttpReceiveResponse(), this function queries the RESPONSE headers
 *   and transforms them into a shape IIRF can send to its client.
 *
 * Arguments:
 *
 *   cfg - IIRF Vdir Configuration structure
 *
 *   pRequest - the HINTERNET for the outbound proxied request. Caller
 *      must have already called WinHttpReceiveResponse().
 *
 *   szStatus - a string, pre-allocated, that will get the HTTP Status response.
 *
 *   status - the actual numeric status.  (input)
 *
 *
 * Returns:
 *
 *   char * - allocated.  Caller must free.  It contains the
 *      string containing all the massaged response headers, suitable for
 *      sending to the IIRF requesting client.
 *
 */
char *IirfProxy_GetResponseHeaders(IirfVdirConfig * cfg,
                                   HINTERNET pRequest,
                                   char * localAddr,
                                   char * szStatus,
                                   /* in */ int status,
                                   const char * serverName,
                                   char * port,
                                   char * https)
{
    CHAR *sRawHeaders= NULL;
    WCHAR *wRawHeaders;
    DWORD dwSize = 0;

    LogMessage(cfg, 4, "Proxy_SetResponseHeaders: starting status %d", status);

    if (status == HTTP_STATUS_OK) {
        LogMessage(cfg, 4, "Proxy_SetResponseHeaders: status OK");

        strcpy_s(szStatus, 32, "200 OK");
    }
    else if (status == HTTP_STATUS_REQUEST_TIMEOUT+10000) {
        LogMessage(cfg, 4, "Proxy_SetResponseHeaders: status TIMEOUT");

        sprintf_s(szStatus, 32, "%3.0i Request Time-out", HTTP_STATUS_REQUEST_TIMEOUT);
    }
    else {
        LogMessage(cfg, 4, "Proxy_SetResponseHeaders: status NOT 200, not TIMEOUT");

        if (status == 404)
            sprintf_s(szStatus, 32, "%3.0i Not Found", status);
        else if (status == 403)
            sprintf_s(szStatus, 32, "%3.0i Forbidden", status);
        else if (status == 401)
            sprintf_s(szStatus, 32, "%3.0i Unauthorized", status);
        else
            sprintf_s(szStatus, 32, "%3.0i", status);
    }

    LogMessage(cfg, 5, "Proxy_SetResponseHeaders: status string '%s'", szStatus);

    if (status != HTTP_STATUS_REQUEST_TIMEOUT+10000) {
        WinHttpQueryHeaders(pRequest,
                            WINHTTP_QUERY_RAW_HEADERS_CRLF,
                            WINHTTP_HEADER_NAME_BY_INDEX,
                            WINHTTP_NO_OUTPUT_BUFFER,
                            &dwSize,
                            WINHTTP_NO_HEADER_INDEX);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            wRawHeaders = (WCHAR*) malloc(dwSize + 2);
            if (!WinHttpQueryHeaders(pRequest,
                                     WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                     WINHTTP_HEADER_NAME_BY_INDEX,
                                     wRawHeaders,
                                     &dwSize,
                                     WINHTTP_NO_HEADER_INDEX)) {
                // FAIL
                LogMessage(cfg, 2, "Proxy_SetResponseHeaders: WinHttpQueryHeaders fail");
                free(wRawHeaders);
                return NULL;
            }

            sRawHeaders= Iirf_WideCharToAscii(wRawHeaders);

            free(wRawHeaders);

            sRawHeaders= IirfProxy_ProcessResponseHeaders(cfg, sRawHeaders, localAddr, szStatus, serverName, port, https);
        }
    }

    return sRawHeaders;
}



void CALLBACK Iirf_WinHttpSslStatusCallback( HINTERNET hInternet,
                                             DWORD_PTR context,
                                             DWORD code,
                                             LPVOID pInfo,
                                             DWORD infoLength)
{
    if (code == WINHTTP_CALLBACK_STATUS_SECURE_FAILURE) {
        IirfVdirConfig * cfg = (IirfVdirConfig *) context;
        DWORD details = (DWORD) pInfo; // do not de-reference
        CHAR buffer[32];
        CHAR * statusDescription = NULL;

        switch (details) {
            case WINHTTP_CALLBACK_STATUS_FLAG_CERT_REV_FAILED:
                statusDescription = "CERT_REV_FAILED";
                break;

            case WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CERT:
                statusDescription = "INVALID_CERT";
                break;

            case WINHTTP_CALLBACK_STATUS_FLAG_CERT_REVOKED:
                statusDescription = "CERT_REVOKED";
                break;

            case WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA:
                statusDescription = "INVALID_CA";
                break;

            case WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID:
                statusDescription = "CERT_CN_INVALID";
                break;

            case WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID:
                statusDescription = "CERT_DATE_INVALID";
                break;

            case WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR:
                statusDescription = "SECURITY_CHANNEL_ERROR";
                break;

            default:
                statusDescription = buffer;
                sprintf_s(buffer, 32, "stat(0x%08X) len(%d)",
                          details, infoLength);
                // workitem http://iirf.codeplex.com/workitem/29924
                if (infoLength > 0 && infoLength < 10) {
                    int i, n;
                    DWORD* eInfo = (DWORD*) pInfo;
                    CHAR extendedBuffer[128];
                    n = (int) infoLength;
                    sprintf_s(extendedBuffer, 128, "stat(0x%08X) len(%d)",
                              details, infoLength);
                    statusDescription = extendedBuffer;
                    for (i=0; i<n; i++) {
                        sprintf_s(buffer, 32, " e[%d]=%08X", i, eInfo[i]);
                        strcat_s(extendedBuffer, 128, buffer);
                    }
                }
                break;
        }

        LogMessage(cfg, 1, "Iirfproxy: SslStatusCallback: %s", statusDescription);
    }
}




/*
 * IirfProxy_RequestHasMessageBody
 *
 * workitem 30306
 *
 * Purpose:
 *
 *   Return a boolean indicating whether the request has a message body, or not.
 *   This is used to determine whether proxying thee request will require
 *   rewriting it first, to the IIRF-as-ISAPI-extension, in order to be able to
 *   read the message body.
 *
 *   According to RFC 2616, Section 4,
 *
 *      The presence of a message-body in a request is signaled by the
 *      inclusion of a Content-Length or Transfer-Encoding header field in the
 *      request's message-headers. A message-body MUST NOT be included in a
 *      request if the specification of the request method (section 5.1.1) does
 *      not allow sending an entity-body in requests.
 *
 * Arguments:
 *
 *   cfg - IIRF Vdir Configuration structure. Used only for logging.
 *
 *   rhRoot - a linked list as generated by IirfProxy_ParseAllRaw, containing the
 *      parsed request headers.
 *
 * Returns:
 *
 *   boolean.  TRUE if the request has a message body, as indicated by the
 *     presence of either the Content-length or Transfer-Encoding header. FALSE
 *     if not.
 *
 */
boolean IirfProxy_RequestHasMessageBody(IirfVdirConfig * cfg, IirfRequestHeader *rhRoot)
{
    boolean hasMessageBody = FALSE;
    IirfRequestHeader *rh = rhRoot;

    if (rh == NULL) return FALSE;

    do {
        if (_stricmp(rh->S[0], "Content-Length")==0 &&
            _stricmp(rh->S[1], "0")!=0) {  // non-zero content-length
            hasMessageBody = TRUE;
        }
        else if (_stricmp(rh->S[0], "Transfer-Encoding")==0) {
            // According to RFC 2616, the presence of the Transfer-Encoding header
            // means a message body is present, regardless of the value of
            // the header (eg, chunked, gzip, ... anything at all).
            hasMessageBody = TRUE;
        }

        rh= rh->Next;
    } while (rh != NULL && !hasMessageBody);

    return hasMessageBody;
}



/*
 * IirfProxy_TryRelayEmptyBodyRequest
 *
 * Purpose:
 *
 *   Handles the proxy communication for any HTTP methods, such as GET or HEAD,
 *   that do not require sending a message-body. For incoming HTTP requests
 *   that include a Content-Length header or a Transfer-Encoding header,
 *   including but not limited to requests that use the POST or PUT methods,
 *   this function returns 1, which indicates to the caller that it must handle
 *   the request specially.
 *
 *   According to RFC 2616, Section 4,
 *
 *      The presence of a message-body in a request is signaled by the
 *      inclusion of a Content-Length or Transfer-Encoding header field in the
 *      request's message-headers. A message-body MUST NOT be included in a
 *      request if the specification of the request method (section 5.1.1) does
 *      not allow sending an entity-body in requests.
 *
 *   In IIRF, requests with a message-body need to be rewritten to the .iirf
 *   extension to be handled by IIRF-as-ISAPI-extension, which allows reading
 *   of the entire message.
 *
 *   The caller is responsible for rewriting the request to a URL ending in .iirf,
 *   which will be handled by IIRF. The rewritten request eventually arrives at IIRF
 *   again, this time through the ISAPI Extension mechanism. And the extension calls
 *   IirfProxy_RelayRequestWithMessageBody() with the appropriate settings.

 *   Ref: David Wang article advising the use of an Extension for Proxy POST :
 *   http://blogs.msdn.com/david.wang/archive/2006/05/10/HOWTO-Access-POST-form-data-with-ISAPI.aspx
 *
 *   Proxying requests with non-empty message body requires installing IIRF as both a Filter and an Extension :
 *   http://blogs.msdn.com/david.wang/archive/2005/11/28/Can-I-Install-an-ISAPI-Filter-as-an-ISAPI-Extension-or-Wildcard-Application-Mapping.aspx

 *
 * Arguments:
 *
 *   pfc - pointer to HTTP_FILTER_CONTEXT for the incoming request.
 *
 *   fqUrl - a string, the fully-qualified URL to proxy the request TO.
 *
 *   origHost - a string, the original host. Optionally NULL.
 *      Caller should pass a non-NULL value to implement ProxyPreserveHost.
 *
 *   pContentChunks - ptr to int that will get the number of response chunks
 *      relayed to the requesting client.  When "Transfer-Encoding: Chunked" is
 *      used, this the number of HTTP chunks. When a non-cnunked protocol is used,
 *      this number represents the number of cycles through the pump.
 *
 *   pContentTotalBytes - ptr to int that will get the number of bytes relayed
 *      to the requesting client.
 *
 * Returns:
 *
 *   DWORD - zero (0) if the zero-body message was proxied. one (1) if
 *      the incoming request includes a message body payload, and thus requires
 *      IIRF to internally rewrite to the IIRF-as-ISAPI-extension.
 *
 */
DWORD IirfProxy_TryRelayEmptyBodyRequest(HTTP_FILTER_CONTEXT * pfc,
                            LPCTSTR fqUrl,
                            LPCTSTR origHost, // workitem 29415
                            int *pContentChunks,
                            int *pContentTotalBytes)
{
    IirfVdirConfig*    cfg       = GetVdirConfigFromFilterContext(pfc);
    CHAR*              varAllRaw = GetServerVariable_AutoFree(pfc, "ALL_RAW");
    CHAR*              varMethod = GetServerVariable_AutoFree(pfc, "REQUEST_METHOD");
    IirfRequestHeader* rhRoot;    // workitem 30306

    LogMessage(cfg, 3, "IirfProxy_TryRelayEmptyBodyRequest: %s", fqUrl);

    rhRoot = IirfProxy_ParseAllRaw(cfg, varAllRaw);

    // workitem 30306 - return 1 (and don't proxy the request) only when a
    // message body is present. Optimize for GET/HEAD/TRACE; if none of those
    // apply, then do a full scan of the request headers.
    if (strcmp("GET", varMethod)!=0 &&
        strcmp("HEAD", varMethod)!=0 &&
        strcmp("TRACE", varMethod)!=0 &&  // message-body disallowed
        IirfProxy_RequestHasMessageBody(cfg, rhRoot)) {
        // Need to read the message body data (eg, POST data). Cannot do it from a
        // ISAPI filter. Must rewrite to the IIRF Extension, which will then do the
        // proxying. Caller will do that.
        IirfProxy_FreeIirfRequestHeaders(rhRoot);
        return 1;
    }
    else {
        DWORD           nRetCode          = HTTP_STATUS_OK;
        HINTERNET       hOpen, hConnection, hRequest;
        int             len;
        CHAR*           varRemoteAddr     = GetServerVariable_AutoFree(pfc, "REMOTE_ADDR");
        CHAR*           varLocalAddr      = GetServerVariable_AutoFree(pfc, "LOCAL_ADDR");
        CHAR*           varReferer        = GetServerVariable_AutoFree(pfc, "HTTP_REFERER");
        CHAR*           varUserAgent      = GetServerVariable_AutoFree(pfc, "HTTP_USER_AGENT");
        const CHAR*     varAccept         = GetServerVariable_AutoFree(pfc, "HTTP_ACCEPT");
        const CHAR*     varServerName     = GetServerVariable_AutoFree(pfc, "SERVER_NAME");
        CHAR*           varMethod         = GetServerVariable_AutoFree(pfc, "REQUEST_METHOD");

        WCHAR *         wReferer          = NULL;
        WCHAR **        pwAccept          = NULL;
        WCHAR           urlDefault[2]     ;
        CHAR *          sHeaders          = NULL;
        DWORD           dwOpt             ;
        char *          errorStage        = NULL;
        BOOL            bStatus           = FALSE;
        BOOL            isChunkedResponse = FALSE;
        WCHAR *         wUrlPathAndQuery  ;
        WCHAR *         wUrl              = NULL;
        WCHAR *         wHostName         = NULL;
        WCHAR *         wUserAgent        = Iirf_AsciiToWideChar(varUserAgent);
        WCHAR *         wMethod           = Iirf_AsciiToWideChar(varMethod);
        WCHAR *         wHeaders          = NULL;
        DWORD           dwRet             = 0;
        DWORD           dwRetLength       = sizeof(DWORD);
        DWORD           dwFlags           = 0;
        URL_COMPONENTS  urlComponents;

#ifdef IIRF_DIAG_PROXY_OPS
        char * diagLogFile = "c:\\inetpub\\iirfLogs\\iirf-proxy.log";
        FILE * proxyLog = _fsopen(diagLogFile, "a+", _SH_DENYNO );
        LogMessage(cfg, 5, "ProxyRequest: open proxy log(0x%08x)", proxyLog);
        fprintf(proxyLog,"\n\n-------------------------------------------------------\n");
        {
            time_t t;
            char TimeBuffer[26] ;
            time(&t);
            ctime_s(TimeBuffer,26,&t);
            // 0123456789012345678901234 5
            // Wed Jan 02 02:03:55 1980\n\0
            TimeBuffer[24]=0; // null out final newline
            fprintf(proxyLog,"%s - Proxy request %s\n", TimeBuffer, fqUrl);
            fprintf(proxyLog,"-------------------------------------------------------\n\n");
            fflush(proxyLog);
        }
#endif
        urlDefault[0]=L'/';
        urlDefault[1]=L'\0';

        *pContentTotalBytes= 0;
        *pContentChunks= 0;

        // crack the url that we are proxing TO
        wUrl= Iirf_AsciiToWideChar(fqUrl);

        ZeroMemory(&urlComponents, sizeof(URL_COMPONENTS));
        urlComponents.dwStructSize = sizeof(URL_COMPONENTS);

        // Set required component lengths to non-zero so that they are cracked.
        urlComponents.dwSchemeLength    = -1;
        urlComponents.dwHostNameLength  = -1;
        urlComponents.dwUrlPathLength   = -1;
        urlComponents.dwExtraInfoLength = -1;

        if (!WinHttpCrackUrl( wUrl, Iirf_ConvertSizeTo32bits(wcslen(wUrl)), 0, &urlComponents)) {
            errorStage = "WinHttpCrackUrl";
            goto Proxy_Fail;
        }

        // NOTE:
        //
        // Don't be fooled by the field names in URL_COMPONENTS. The
        // lpszScheme is actually a LPWSTR. It *should* be named
        // lpwszScheme, but it is not. The same is true for all the strings
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

        // terminate hostname for later use
        //urlComponents.lpszHostName[urlComponents.dwHostNameLength]=L'\0';
        len = urlComponents.dwHostNameLength;
        wHostName = (WCHAR*) malloc((len+1) * sizeof(WCHAR));
        wcsncpy_s(wHostName, len+1, urlComponents.lpszHostName, len);
        wHostName[urlComponents.dwHostNameLength]=L'\0';

        if (urlComponents.nScheme == INTERNET_SCHEME_HTTPS)
            dwFlags |= WINHTTP_FLAG_SECURE;

        wUrlPathAndQuery = (urlComponents.lpszUrlPath[0]==L'\0')
            ? urlDefault
            : urlComponents.lpszUrlPath;

        LogMessage(cfg, 4, "ProxyRequest: host(%S)  path+query(%S)", wHostName, wUrlPathAndQuery);

        {
            CHAR * sTargetHost = (origHost == NULL)
                ? Iirf_WideCharToAscii(wHostName)
                : origHost;
            sHeaders = IirfProxy_GenProxyRequestHeadersString(cfg, rhRoot, sTargetHost, varServerName, varLocalAddr, varRemoteAddr, 0);
            wHeaders= Iirf_AsciiToWideChar(sHeaders);
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
            goto Proxy_Fail;
        }

        dwOpt = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        if (!WinHttpSetOption(hOpen, WINHTTP_OPTION_REDIRECT_POLICY, &dwOpt, sizeof(DWORD))) {
            errorStage = "WinHttpSetOption";
            goto Proxy_Fail;
        }

        if (!WinHttpSetTimeouts(hOpen,
                                cfg->ProxyTimeout[0]*1000, // dwResolveTimeout
                                cfg->ProxyTimeout[1]*1000, // dwConnectTimeout
                                cfg->ProxyTimeout[2]*1000, // dwSendTimeout
                                cfg->ProxyTimeout[3]*1000  // dwReceiveTimeout
                )) {
            errorStage = "WinHttpSetTimeouts";
            goto Proxy_Fail;
        }

        pwAccept= Iirf_wTokenizeAccept(cfg, varAccept);

        wReferer = (varReferer[0]=='\0')
            ? WINHTTP_NO_REFERER
            : Iirf_AsciiToWideChar(varReferer);

        LogMessage(cfg, 4, "ProxyRequest: WinHttpConnect %S %d", wHostName, urlComponents.nPort);

        hConnection = WinHttpConnect(hOpen, wHostName, urlComponents.nPort, 0);
        if (hConnection == NULL) {
            errorStage = "WinHttpConnect";
            goto Proxy_Fail;
        }

        LogMessage(cfg, 4, "ProxyRequest: WinHttpOpenRequest: %s %S",
                   varMethod, urlComponents.lpszUrlPath);

        hRequest = WinHttpOpenRequest(hConnection,
                                      wMethod,                   // GET, HEAD, OPTIONS, etc?
                                      urlComponents.lpszUrlPath, //
                                      NULL,                      // defaults to L"HTTP/1.1",
                                      wReferer,                  // Maybe NULL
                                      pwAccept,
                                      dwFlags);
        if (hRequest == NULL) {
            errorStage = "WinHttpOpenRequest";
            goto Proxy_Fail;
        }

        LogMessage(cfg, 4, "ProxyRequest: WinHttpAddRequestHeaders");

        // If proxying an https request, then register for SSL callbacks.
        if ((dwFlags & WINHTTP_FLAG_SECURE) == WINHTTP_FLAG_SECURE) {

            // First, set the IirfVdirConfig as the request context.
            // This will be retrieved in the callback and used for
            // logging purposes.
            if (! WinHttpSetOption(hRequest,
                                   WINHTTP_OPTION_CONTEXT_VALUE,
                                   &cfg,
                                   sizeof(cfg))) {
                // It failed. In this case there's no sense setting the
                // status callback, since there's nothing the callback
                // can do with it, without the vdir config info
                // (the logfile).
                LogMessage(cfg, 1,
                           "ProxyRequest: WinHttpSetOption: (error=%d) (Non-fatal)",
                           GetLastError());
            }
            else {
                // success
                // ok, now set the status callback
                WINHTTP_STATUS_CALLBACK statusCallback =
                    WinHttpSetStatusCallback(hRequest,
                                             Iirf_WinHttpSslStatusCallback,
                                             WINHTTP_CALLBACK_FLAG_SECURE_FAILURE,
                                             (DWORD_PTR) NULL);  // must be NULL
                if (statusCallback == WINHTTP_INVALID_STATUS_CALLBACK) {
                    LogMessage(cfg, 1,
                               "ProxyRequest: WinHttpSetStatusCallback: (error=%d) (Non-fatal)",
                               GetLastError());
                }
            }
        }

        if (! WinHttpAddRequestHeaders(hRequest, wHeaders, -1L, WINHTTP_ADDREQ_FLAG_ADD)) {
            errorStage = "WinHttpAddRequestHeaders";
            goto Proxy_Fail;
        }

        LogMessage(cfg, 4, "ProxyRequest: WinHttpSendRequest");
        if ((! WinHttpSendRequest(hRequest,
                                  WINHTTP_NO_ADDITIONAL_HEADERS,
                                  0,
                                  WINHTTP_NO_REQUEST_DATA,
                                  0,
                                  0,
                                  0))
            && (GetLastError() != ERROR_IO_PENDING)) {
            errorStage = "WinHttpSendRequest";
            goto Proxy_Fail;
        }


        LogMessage(cfg, 4, "ProxyRequest: WinHttpReceiveResponse");

        // Wait for the request to complete.
        if (!WinHttpReceiveResponse( hRequest, NULL)) {
            if (GetLastError() == ERROR_WINHTTP_TIMEOUT)
                nRetCode = HTTP_STATUS_REQUEST_TIMEOUT+10000;
            else
                LogMessage(cfg, 1, "ProxyRequest: Error in WinHttpReceiveResponse(): %d", GetLastError());
        }
        else {
            LogMessage(cfg, 4, "ProxyRequest: WinHttpQueryHeaders");
            // Get the Status Code
            if (! WinHttpQueryHeaders(hRequest,
                                      WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                      WINHTTP_HEADER_NAME_BY_INDEX,
                                      &dwRet,
                                      &dwRetLength,
                                      WINHTTP_NO_HEADER_INDEX)) {
                errorStage = "WinHttpQueryHeaders";
                goto Proxy_Fail;
            }
            nRetCode = dwRet;
            LogMessage(cfg, 4, "ProxyRequest: WinHttpQueryHeaders: status %d", nRetCode);
        }

        {
            CHAR szStatus[32];
            char * sRawRespHeaders = NULL;
            char * port = NULL;
            char * https = NULL;
            if (cfg->rootPpr != NULL) {
                // need these only if ProxyPassReverse directive is present
                port = GetServerVariable(pfc, "SERVER_PORT");
                https = GetServerVariable(pfc, "HTTPS");
            }
            ZeroMemory(szStatus, sizeof(szStatus));

            sRawRespHeaders= IirfProxy_GetResponseHeaders(cfg, hRequest, varLocalAddr, szStatus, nRetCode, varServerName, port, https);

            if (port!=NULL) free (port);
            if (https!=NULL) free (https);

            // workitem 25703, 29250
            isChunkedResponse = (sRawRespHeaders)
                ? IirfProxy_IsChunkedHeaderPresent(cfg, sRawRespHeaders)
                : FALSE;

            //  Send header back to client
            pfc->ServerSupportFunction (pfc,
                                        SF_REQ_SEND_RESPONSE_HEADER,
                                        (PVOID)szStatus,
                                        (ULONG_PTR)((sRawRespHeaders)? sRawRespHeaders:""),
                                        (ULONG_PTR) NULL );
            if (sRawRespHeaders) free(sRawRespHeaders);
        }


        if  (nRetCode != HTTP_STATUS_REQUEST_TIMEOUT &&
             nRetCode != HTTP_STATUS_REQUEST_TIMEOUT+10000) {

            DWORD nRead = 0l;
            DWORD nWritten;
            int dwSize= 0;
            int bufSize = IIRF_PROXY_CHUNK_SIZE; // TODO: make this size configurable.
            CHAR * buffer = (CHAR *) malloc(bufSize);
            char szbuf[16];  // for the chunk frame data

            do {
                dwSize = 0;
                if (!WinHttpQueryDataAvailable( hRequest, &dwSize)) {
                    errorStage = "WinHttpQueryDataAvailable";
                    goto Proxy_Fail;
                }
                nRead = 0l;
                if (dwSize>0) {
                    int sizeToRead = (dwSize > bufSize-2)? bufSize-2 : dwSize;
                    LogMessage(cfg, 4, "ProxyRequest: WinHttpReadData %d", sizeToRead);
                    if (!WinHttpReadData(hRequest, buffer, sizeToRead, &nRead)) {
                        errorStage = "WinHttpReadData";
                        goto Proxy_Fail;
                    }
                    LogMessage(cfg, 5, "ProxyRequest: WinHttpReadData nRead= %d", nRead);
                    if (nRead > 0l) {
                        // Need to properly implement RFC2616 here wrt chunking.  On
                        // reading, IIS handles the un-chunking transparently:
                        // WinHttpReadData gets the data, strips chunking metadata,
                        // and hands it to the app.  On Writeclient, though, the app
                        // needs to inject the chunk framing into the data stream.
                        //
                        // A chunk Looks like
                        //    1*HEX CRLF
                        //    data  CRLF
                        //
                        // The hex digits provide the length, and are string encoded.
                        //
                        // The last chunk must be a zero-size chunk. It looks like:
                        //    0 CRLF
                        //    CRLF
                        //
                        // Where the zero is actuallly 0x30 (Ascii 0).
                        //
                        // See  http://tools.ietf.org/html/rfc2616#page-25 .
                        //

                        // workitem 25703
                        if (isChunkedResponse) {
                            // the start frame for this chunk
                            sprintf_s(szbuf, sizeof(szbuf)/sizeof(szbuf[0]),
                                      "%0x\r\n", nRead);
                            nWritten = Iirf_ConvertSizeTo32bits(strlen(szbuf));
                            pfc->WriteClient(pfc, szbuf, &nWritten, 0);
                        }

                        // the data for the chunk
                        nWritten = nRead;
                        pfc->WriteClient(pfc, buffer, &nWritten, 0);

                        if (isChunkedResponse) {
                            // the end frame for this chunk
                            nWritten = 2;
                            pfc->WriteClient(pfc, "\r\n", &nWritten, 0);
                        }

#ifdef IIRF_DIAG_PROXY_OPS
                        LogMessage(cfg, 5, "ProxyRequest: writing proxy log bytes(%d)", nRead);
                        fwrite(buffer, 1, nRead, proxyLog);
#endif
                        (*pContentTotalBytes) += nRead;
                        (*pContentChunks)++;
                    }
                }
            } while(nRead > 0 && (*pContentChunks) < IIRF_PROXY_MAX_CHUNKS_TO_READ);

            if (isChunkedResponse) {
                // the final, zero-length chunk
                sprintf_s(szbuf, sizeof(szbuf)/sizeof(szbuf[0]), "0\r\n\r\n");
                nWritten = Iirf_ConvertSizeTo32bits(strlen(szbuf));
                pfc->WriteClient(pfc, szbuf, &nWritten, 0);
            }

            LogMessage(cfg, 4, "ProxyRequest: segments(%d) totalBytes(%d)",
                       (*pContentChunks), (*pContentTotalBytes));

            // The totalBytes may not agree with Content-Length, if the method
            // is HEAD.  According to RFC 2616, Section 9, the server MUST NOT
            // return a message-body in the response to a HEAD request.

            free(buffer);
            if ((*pContentChunks) < IIRF_PROXY_MAX_CHUNKS_TO_READ)
                SetLastError( NO_ERROR );
            else {
                errorStage = "ReadData/WriteClient";
                SetLastError( ERROR_IO_INCOMPLETE );
            }

            //nRetCode = HTTP_STATUS_OK;
        }



    Proxy_Fail:
        if (errorStage)
            LogMessage(cfg, 1, "IirfProxy_TryRelayEmptyBodyRequest: Error in %s(): %d", errorStage, GetLastError());


        if (hRequest != NULL)    WinHttpCloseHandle(hRequest);
        if (hConnection != NULL) WinHttpCloseHandle(hConnection);
        if (hOpen != NULL)       WinHttpCloseHandle(hOpen);
        if (pwAccept)    Iirf_ReleaseArrayWchar(cfg, pwAccept);
        if (wHostName)   free(wHostName);
        if (wReferer)    free(wReferer);
        if (wUrl)        free(wUrl);
        if (sHeaders)    free(sHeaders);
        if (wHeaders)    free(wHeaders);
        if (wUserAgent)  free(wUserAgent);
        if (wMethod)     free(wMethod);

#ifdef IIRF_DIAG_PROXY_OPS
        fflush(proxyLog);
        fclose(proxyLog);
#endif

    }


    return 0;
}

