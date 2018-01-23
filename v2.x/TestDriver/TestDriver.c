/*
 * TestDriver.c
 *
 * Test driver module for the Isapi Rewrite filter.
 * This module links to the ISAPI filter DLL, and drives it.
 * This permits testing of the RewriteRules against a specific set of URLs,
 * from the command line, without needing to configure the ISAPI filter to IIS.
 * Output is sent to the console.
 *
 * Use this app to verify that the rewrite rules you have
 * authored are working as desired.
 *
 * ==================================================================
 *
 * License
 * ---------------------------------
 *
 * Ionic's ISAPI Rewrite Filter is an add-on to IIS that can
 * rewrite URLs.  IIRF and its documentation is distributed under
 * the Microsoft Permissive License, spelled out below.
 *
 * IIRF depends upon PCRE, which is licensed independently and
 * separately.  Consult the License.pcre.txt file for details.
 *
 *
 * --------------------------------------------
 * Microsoft Permissive License (Ms-PL)
 * Published: October 12, 2006
 *
 * This license governs use of the accompanying software. If you
 * use the software, you accept this license. If you do not accept
 * the license, do not use the software.
 *
 * 1. Definitions
 *
 * The terms "reproduce," "reproduction," "derivative works," and
 * "distribution" have the same meaning here as under
 * U.S. copyright law.
 *
 * A "contribution" is the original software, or any additions or
 * changes to the software.
 *
 * A "contributor" is any person that distributes its contribution
 * under this license.
 *
 * "Licensed patents" are a contributor's patent claims that read
 * directly on its contribution.
 *
 * 2. Grant of Rights
 *
 * (A) Copyright Grant- Subject to the terms of this license,
 * including the license conditions and limitations in section 3,
 * each contributor grants you a non-exclusive, worldwide,
 * royalty-free copyright license to reproduce its contribution,
 * prepare derivative works of its contribution, and distribute its
 * contribution or any derivative works that you create.
 *
 * (B) Patent Grant- Subject to the terms of this license,
 * including the license conditions and limitations in section 3,
 * each contributor grants you a non-exclusive, worldwide,
 * royalty-free license under its licensed patents to make, have
 * made, use, sell, offer for sale, import, and/or otherwise
 * dispose of its contribution in the software or derivative works
 * of the contribution in the software.
 *
 * 3. Conditions and Limitations
 *
 * (A) No Trademark License- This license does not grant you rights
 * to use any contributors' name, logo, or trademarks.
 *
 * (B) If you bring a patent claim against any contributor over
 * patents that you claim are infringed by the software, your
 * patent license from such contributor to the software ends
 * automatically.
 *
 * (C) If you distribute any portion of the software, you must
 * retain all copyright, patent, trademark, and attribution notices
 * that are present in the software.
 *
 * (D) If you distribute any portion of the software in source code
 * form, you may do so only under this license by including a
 * complete copy of this license with your distribution. If you
 * distribute any portion of the software in compiled or object
 * code form, you may only do so under a license that complies with
 * this license.
 *
 * (E) The software is licensed "as-is." You bear the risk of using
 * it. The contributors give no express warranties, guarantees or
 * conditions. You may have additional consumer rights under your
 * local laws which this license cannot change. To the extent
 * permitted under your local laws, the contributors exclude the
 * implied warranties of merchantability, fitness for a particular
 * purpose and non-infringement.
 * --------------------------------------------
 * end-of-license
 *
 * ==================================================================
 *
 *
 *
 * Copyright (c) Dino Chiesa 2010
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <WTypes.h>
#include <WinHttp.h>
#include <HttpFilt.h>

#include <pcre.h>

#include "IIRF.h"

#define TEST_URLS "SampleUrls.txt"


// externs
extern void LogMessage( IirfVdirConfig * cfg, int MsgLevel, const char * format, ... );    // IirfLogging.c
extern IirfVdirConfig * Iirf_IsapiFilterTestSetup(char * psz_iniDirName) ;
extern int Iirf_EvaluateRules(HTTP_FILTER_CONTEXT * pfc, char * subject, int depth, RewriteRule ** matchedRule, char ** result);
extern char * Iirf_GetVersion(void);
extern char * Iirf_GetBuildSig(void);



void Ascii2Wide(LPCSTR s, LPWSTR * w)
{
    DWORD len = Iirf_ConvertSizeTo32bits(strlen(s) + 1);
    (*w)= malloc(len * sizeof(wchar_t));

    ZeroMemory(*w, len*2);
    if (0 == MultiByteToWideChar(CP_ACP, 0, s, len, *w, len*2)) {
        free(*w);
        *w = NULL;
    }
}


/*
 * puts a newly allocated (char *) into the arg s. The new char* holds
 * an ASCII version of the wide string.  Caller must free s.
 */
void Wide2Ascii(LPCWSTR w, LPSTR * s)
{
    int len2= Iirf_ConvertSizeTo32bits(lstrlenW(w));
    (*s) = (char*) malloc(len2+1);
    //fprintf(stderr,"U2A: alloc %d bytes\n", len2);
    ZeroMemory(*s, len2+1);
    if (0 == WideCharToMultiByte(CP_ACP, 0, w, len2, *s, len2, NULL, NULL)) {
        // FAIL
        free(*s);
        *s = NULL;
    }
    else (*s)[len2]='\0';
}



/* Caches for various server variables */
char * lastCrackedHttps;
char * lastCrackedServerPort;
char * lastCrackedQueryString;
char * lastCrackedHost;
char * lastCrackedUrl;
char * lastCrackedRequestUri;

BOOL CrackUrl(LPCSTR url, URL_COMPONENTS ** urlComponents)
{
    wchar_t * wUrl;
    char *s= NULL;
    wchar_t t;

    (*urlComponents) = malloc(sizeof(URL_COMPONENTS));

    //printf("\nCRACK '%s'\n", url);

    Ascii2Wide(url, &wUrl);

    // Initialize the URL_COMPONENTS structure.
    ZeroMemory(*urlComponents, sizeof(URL_COMPONENTS));

    (*urlComponents)->dwStructSize = sizeof(URL_COMPONENTS);

    // Set required component lengths to non-zero so that they are cracked.
    (*urlComponents)->dwSchemeLength    = -1;
    (*urlComponents)->dwHostNameLength  = -1;
    (*urlComponents)->dwUrlPathLength   = -1;
    (*urlComponents)->dwExtraInfoLength = -1;

    //printf("CrackUrl: %S. (len:=%d)", wUrl, wcslen(wUrl));

    if (!WinHttpCrackUrl( wUrl, Iirf_ConvertSizeTo32bits(wcslen(wUrl)), 0, (*urlComponents)))
    {
        // printf("CrackUrl: failed. (error=0x%08x  %d)",
        // GetLastError(), GetLastError());
        free(*urlComponents);
        free(wUrl);
        *urlComponents= NULL;
        return FALSE;
    }

    // must keep wUrl. The urlComponents structure points into it.
    // This is a leak!

    // set other "fake" server variables based on the URL
    // HTTPS
    if ((*urlComponents)->nScheme == INTERNET_SCHEME_HTTPS) {
        lastCrackedHttps = "on";
        lastCrackedServerPort = "443";
    }
    else {
        lastCrackedHttps = "off";
        lastCrackedServerPort = "80";
    }

    // QueryString
    if (lastCrackedQueryString) free(lastCrackedQueryString);
    if ((*urlComponents)->dwExtraInfoLength > 0)
        Wide2Ascii((*urlComponents)->lpszExtraInfo+1, &lastCrackedQueryString);
    else
        lastCrackedQueryString = _strdup("");

    // REQUEST_URI - url path and query string
    if (lastCrackedRequestUri) free(lastCrackedRequestUri);
    Wide2Ascii((*urlComponents)->lpszUrlPath, &lastCrackedRequestUri);

    // URL - path only
    if (lastCrackedUrl) free(lastCrackedUrl);
    t= (*urlComponents)->lpszUrlPath[(*urlComponents)->dwUrlPathLength];
    (*urlComponents)->lpszUrlPath[(*urlComponents)->dwUrlPathLength]=L'\0';
    Wide2Ascii((*urlComponents)->lpszUrlPath, &lastCrackedUrl);
    (*urlComponents)->lpszUrlPath[(*urlComponents)->dwUrlPathLength]= t;

    // HTTP_HOST
    if (lastCrackedHost) free(lastCrackedHost);
    (*urlComponents)->lpszHostName[(*urlComponents)->dwHostNameLength]=L'\0';
    Wide2Ascii((*urlComponents)->lpszHostName, &lastCrackedHost);
    (*urlComponents)->lpszHostName[(*urlComponents)->dwHostNameLength]=L'/';

    return TRUE;
}





void * __stdcall TestAllocMem(HTTP_FILTER_CONTEXT *pfc,
                              DWORD dwSize,
                              DWORD p2)
{
    void * ptr = malloc(dwSize);
    return ptr;
}





/*
 * TestGetServerVariable
 *
 * This fn returns mock values for some server variables. It is
 * installed into the mock HTTP_FILTER_CONTEXT by the startup code for
 * TestDriver.  Then, when GetServerVariable in Rewriter.c invokes
 * pfc->GetServerVariable, this fn gets activated.
 *
 * It does not support the full set of server variables.
 *
 */
BOOL __stdcall TestGetServerVariable( HTTP_FILTER_CONTEXT *pfc,
                                      LPSTR lpszVariableName,
                                      LPVOID lpwBuffer,
                                      LPDWORD lpdwSize )
{
    /* The lastCrackedXxxx variables are set by CrackUrl() */

    char * s = NULL;
    if (_strnicmp(lpszVariableName, "QUERY_STRING", strlen("QUERY_STRING")) == 0) {
        s = lastCrackedQueryString;
    }
    else if (_strnicmp(lpszVariableName, "URL", strlen("URL")) == 0) {
        // I think this will never happen because of logic in GetServerVariable()
        // within Rewriter.c
        s = lastCrackedUrl;
    }
    else if (_strnicmp(lpszVariableName, "HTTPS", strlen("HTTPS")) == 0) {
        s = lastCrackedHttps;
    }
    else if (_strnicmp(lpszVariableName, "HTTP_HOST", strlen("HTTP_HOST")) == 0) {
        s = lastCrackedHost;
    }
    else if (_strnicmp(lpszVariableName, "SERVER_PORT", strlen("SERVER_PORT")) == 0) {
        s = lastCrackedServerPort;
    }

    if (s == NULL) {
        printf ("\n***\nRetrieving server variable that is not supported by TestDriver (%s)\n",
                lpszVariableName);
        return FALSE;
    }

    if (*lpdwSize == 0) {
        *lpdwSize = Iirf_ConvertSizeTo32bits(strlen(s));
    }
    else {
        strncpy_s( lpwBuffer, *lpdwSize, s, _TRUNCATE );
    }

    return TRUE;
}



static char delims[]= " \n\r\t";

int ProcessUrls(IirfVdirConfig * cfg, char * SampleUrlsFile)
{
    FILE *infile;
    int lineNum=0;
    char line[4096];
    char resultBuf[4096];
    char *p0, *p1, *p2, *p3;
    char * resultString;
    char * actualResult ;
    int rc;
    int errorCount= 0;
    int uncheckedResults = 0;
    int expectedResultsProcessed= 0;
    int len;
    boolean RecordOriginalUrl= FALSE;
    HTTP_FILTER_CONTEXT fc;
    IirfRequestContext ctx;
    RewriteRule *matchedRule;
    URL_COMPONENTS * urlComponents;
    //char * strtokContext= NULL;

    // setups
    ctx.VdirConfig = cfg;
    ctx.Magic = IIRF_CONTEXT_MAGIC_NUMBER;

    fc.pFilterContext = &ctx;
    fc.GetServerVariable = TestGetServerVariable;
    fc.Revision = 1;
    fc.fIsSecurePort = 0;
    fc.AllocMem = TestAllocMem;

    lastCrackedHost = NULL;
    lastCrackedUrl = NULL;
    lastCrackedQueryString = NULL;
    lastCrackedRequestUri = NULL;

    printf("Processing URLs...(%s)\n\n", SampleUrlsFile);

    fopen_s(&infile, SampleUrlsFile, "r");
    if (infile==NULL) {
        printf("Cannot open Urls file '%s'\n", SampleUrlsFile);
        return -99;
    }

    while (TRUE) {
        lineNum++;
        if (fgets((char *)line, sizeof(line)-2, infile) == NULL) break;

        len = Iirf_ConvertSizeTo32bits(strlen(line));
        line[len+1] = '\0';         // add a 2nd terminator after end-of-line
        p1= line;

        while (isspace(*p1)) p1++;  // skip leading spaces
        if (*p1=='\0') continue;    // empty line
        if (*p1=='#') continue;     // comment line

        //DebugBreak();

        p2 = p1;
        // find the first space:
        while((*p2 != ' ')&&(*p2 != '\t')&&(*p2 != '\n')&&(*p2 != '\r')) p2++;
        *p2++='\0'; // terminate and advance

        if (_strnicmp(p1, "http://", 7) == 0 ||
            _strnicmp(p1, "https://", 8) == 0) {
            p0 = p1;
        }
        else {
            char * mockSchemeAndHost = "http://www.example.com";
            size_t len= strlen(p1) + strlen(mockSchemeAndHost) + 2;
            p0 = malloc(len);
            strcpy_s(p0, len, mockSchemeAndHost);
            strcat_s(p0, len, p1);
            // leak p0
        }

        if (CrackUrl(p0, &urlComponents)) {
            char *url2 = NULL;
            Wide2Ascii(urlComponents->lpszUrlPath, &url2);
            p1 = url2;
            // leak url2

            ctx.InterimUrl= lastCrackedUrl;
            ctx.InterimMethod= "GET";
            ctx.RequestUri= lastCrackedRequestUri;
            ctx.PhysicalPath= "c:\\files\\docroot?";
        }
        else {
            LogMessage(cfg, 1, "DoRewrites: Bad Url format: '%s'\n", p1);
            continue;
        }

        // Find the expected result.
        // advance p2 past intervening whitespace
        while((*p2 == ' ')||(*p2 == '\n')||(*p2 == '\r')||(*p2 == '\t')) p2++;

        if (*p2=='\0') {
            // no expected result
            p2 = NULL;
        }
        else {
            expectedResultsProcessed++;
            p3 = p2 + strlen(p2) - 1;    // get the last char in the string (again)
            // trim trailing whitespace
            while((*p3 == ' ')||(*p3 == '\n')||(*p3 == '\r')||(*p3 == '\t')) *p3--='\0';
        }

        //len= Iirf_ConvertSizeTo32bits(strlen(p1));

        LogMessage(cfg, 1, "DoRewrites: Url: '%s'\n", p1);

        rc= Iirf_EvaluateRules(&fc, p1, 0, &matchedRule, &resultString);

        if (rc == 0) {
            printf("\nNO REWRITE '%s' ==> --\n", p1);
            actualResult = "NO REWRITE";
        }
        else if (rc == 1) {
            printf("\nREWRITE '%s' ==> '%s'\n", p1, resultString);
            actualResult = resultString;
            // leak
            //free(resultString);
        }
        else if (rc == 999) {
            printf("\nPROXY '%s' ==> '%s'\n", p1, resultString);
            if (matchedRule->ProxyPreserveHost)
                printf("    (ProxyPreserveHost)\n");
            actualResult = resultString;
        }
        else if (rc == 1200) {
            printf("\nSTATUS\n", p1);
            actualResult = "STATUS";
            // leak
            //free(resultString);
        }
        else if (rc == 1403) {
            printf("\nFORBIDDEN '%s' \n", p1);
            actualResult = "FORBIDDEN";
            // leak
            //free(resultString);
        }
        else if (rc == 1404) {
            printf("\nNOT FOUND '%s' \n", p1);
            actualResult = "NOT FOUND";
            // leak
            //free(resultString); /* leak */
        }
        else {
            rc-=1000;
            printf("\nREDIRECT %d '%s' ==> '%s'\n", rc, p1, resultString);
            sprintf_s(resultBuf, sizeof(resultBuf)/sizeof(resultBuf[0]),
                      "REDIRECT %d %s", rc, resultString);
            actualResult = resultBuf;
            // leak
            //free(resultString);
        }

        if ( (p2!=NULL) && (*p2 != '\0')) {
            if (strcmp(p2, actualResult)==0)
                printf("OK\n\n");
            else {
                if ((strcmp("NO REWRITE", actualResult)==0) && (strcmp(p1, p2) == 0)) {
                    printf("OK\n\n");
                }
                else {
                    printf("ERROR expected(%s)\n        actual(%s)\n\n", p2, actualResult);
                    errorCount++;
                }
            }
        }
        else {
            uncheckedResults++;
        }
    }

    if (expectedResultsProcessed != 0) {
        printf ("\n%d Errors in %d Total Trials\n", errorCount, expectedResultsProcessed);
        if (uncheckedResults > 0)
            printf ("    (%d results were not checked)\n", uncheckedResults);
    }

    fclose(infile);
    return errorCount;
}


void Usage(char *appname)
{
    printf("\nTestDriver.exe\n");
    printf("  tests urls and rules for IIRF.\n");
    printf("  This tool is linked with '%s'.\n", Iirf_GetVersion());
    printf("  The IIRF library was built '%s'\n\n", Iirf_GetBuildSig());
    printf("usage:\n");
    printf("  %s -d <directory>\n\n", appname);
    printf("  options:\n");
    printf("   -d <dir>   reads the ini file and '%s' from the \n",  TEST_URLS);
    printf("              given directory.  (The default is to read them\n");
    printf("              from the current working directory. \n\n\n");
}


int main(int argc, char **argv)
{
    char IniDir[_MAX_PATH];
    char FullpathUrls[_MAX_PATH];
    IirfVdirConfig * config;
    int errorCount = 0;

    if (argc==3) {
        const char * dirSwitch = "-d";

        if (_strnicmp(argv[1], dirSwitch, strlen(dirSwitch))==0) {
            strncpy_s(IniDir, MAX_PATH, argv[2], _MAX_PATH-1);
            sprintf_s(FullpathUrls, _MAX_PATH,"%s\\%s", argv[2], TEST_URLS);
        }
        else {
            Usage(argv[0]);
            return -1;
        }
    }

    else {
        // for debugging purposes only
        //char * dir = "C:\\dev\\codeplex\\iirf\\v2.x\\tests\\RainyCity";
        //strncpy_s(IniDir, MAX_PATH, dir, _MAX_PATH-1);
        //sprintf_s(FullpathUrls, _MAX_PATH,"%s\\%s", dir, TEST_URLS);
        Usage(argv[0]);
        return -1;
    }

    // signon
    printf("TestDriver: linked with '%s'.\n", Iirf_GetVersion());
    printf("TestDriver: The IIRF library was built on '%s'\n\n", Iirf_GetBuildSig());

    config= Iirf_IsapiFilterTestSetup(IniDir);

    errorCount = ProcessUrls(config, FullpathUrls);

    return errorCount;
}
