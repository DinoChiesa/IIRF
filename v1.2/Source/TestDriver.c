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
 * Copyright (c) Microsoft Corporation, 2005, 2006, 2007.  All rights reserved.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <WTypes.h>

#include <pcre.h>

#include <HttpFilt.h>

#include "IIRF.h"

#define DIR_SWITCH "-d"
#define TEST_URLS "SampleUrls.txt"

// externs
extern int EvaluateRules(HTTP_FILTER_CONTEXT * pfc, 
                         HTTP_FILTER_AUTH_COMPLETE_INFO * pHeaderInfo,
                         char * subject,
                         int depth, 
                         /* out */ char **result,
                         /* out */ boolean * pRecordOriginalUrl);
extern void IsapiFilterTestSetup(char * psz_iniDirName);


int ProcessUrls(char * SampleUrlsFile) 
{
    FILE *infile; 
    int lineNum=0; 
    char line[2048];
    char resultBuf[2048];
    char *p1, *p2;
    char * resultString;
    char * actualResult ;
    int rc;
    int errorCount= 0;
    int expectedResultsProcessed= 0;
    int len, lineLen;
    boolean RecordOriginalUrl= FALSE;
    char * StrtokContext= NULL;

    printf("Processing URLs...(%s)\n\n", SampleUrlsFile);

    fopen_s(&infile, SampleUrlsFile, "r");
    if (infile==NULL) {
        printf("Cannot open Urls file '%s'\n", SampleUrlsFile);
        return 1;
    }

    while (TRUE) {
        lineNum++;
        if (fgets((char *)line, sizeof(line)-2, infile) == NULL) break;

        lineLen = strlen(line);
        line[lineLen+1] = '\0'; // add a 2nd terminator after end-of-line
        p1= line;
        while (isspace(*p1)) p1++;

        // split the line by spaces or TAB
        p1= strtok_s(p1, " \t", &StrtokContext);  // get the url

        if (p1 == NULL) continue;   // empty line
        if (*p1=='\0') continue;    // empty line
        if (*p1=='#') continue;     // comment line
        len= strlen(p1);
        p2= p1 + len + 1; // get the expected result (maybe nothing)
        if (p2 - line > lineLen) p2 = NULL;
        if ((p2!=NULL) && (*p2 != '\0'))
        {
            char *p3; 
            while((*p2 == ' ')||(*p2 == '\t')) p2++;       // skip leading spaces and TABs
            p3= p2 + strlen(p2) - 1; 
            while((*p3 == ' ')||(*p3 == '\n')||(*p3 == '\r')||(*p3 == '\t')) *p3--='\0'; // trim trailing whitespace
            expectedResultsProcessed++; 
        }


        while ((len>1) && (isspace(p1[len-1]))) {
            p1[len-1]='\0';
            len= strlen(p1);
        }

        rc= EvaluateRules(NULL, NULL, p1, 0, &resultString, &RecordOriginalUrl);

        if (rc == 0) {
            printf("\nNO ACTION '%s' ==> --\n\n", p1);
            actualResult = "NO REWRITE";
        }
        else if (rc == 1) {
            printf("\nREWRITE '%s' ==> '%s'\n\n", p1, resultString);
            actualResult = resultString;
        }
        else if (rc == 999) {
            printf("\nPROXY '%s' ==> '%s'\n", p1, resultString);
            actualResult = resultString;
        }
        else if (rc == 200) {
            printf("\nSTATUS\n", p1);
            actualResult = "STATUS";
            //free(resultString); 
        }
        else if (rc == 403) {
            printf("\nFORBIDDEN '%s' \n\n", p1);
            actualResult = "FORBIDDEN";
        }
        else if (rc == 404) {
            printf("\nNOT FOUND '%s' \n\n", p1);
            actualResult = "NOT FOUND";
        }
        else {
            printf("\nREDIRECT %d '%s' ==> '%s'\n", rc, p1, resultString);
            sprintf_s(resultBuf, sizeof(resultBuf)/sizeof(resultBuf[0]), 
                      "REDIRECT %d %s", rc, resultString);
            actualResult = resultBuf;
        }
        if ( (p2!=NULL) && (*p2 != '\0'))
        {
            if (strcmp(p2, actualResult)==0) 
                printf("OK\n");
            else {
                if ( (strcmp("NO REWRITE", actualResult)==0) &&
                     (strcmp(p1, p2) == 0))
                {
                    printf("OK\n");
                }
                else {
                    printf("ERROR expected(%s)\n        actual(%s)\n", p2, actualResult);
                    errorCount++;
                }
            }
        }

        //else 
        //printf("\n'%s' ==>  I don't know??\n\n", p1);
    }

    if (expectedResultsProcessed != 0)
    {
        printf ("\n%d Errors in %d Total Trials\n", errorCount, expectedResultsProcessed);
    }

    fclose(infile);
    return errorCount;
}


void Usage(char *appname)
{
    printf("\nTestDriver.exe\n");
    printf("  tests urls and rules for IIRF.\n\n");
    printf("usage:\n");
    printf("  %s -d <directory>\n\n", appname);
    printf("  options:\n");
    printf("   -d <directory>    reads the ini file and '%s' from the \n",  TEST_URLS);
    printf("                     given directory.  (The default is to read them\n");
    printf("                     from the current working directory. \n\n\n");
}


int main(int argc, char **argv)
{
    char IniDir[_MAX_PATH];
    char FullpathUrls[_MAX_PATH];
    int errorCount;
    
    if (argc==3)
    {
        if (_strnicmp(argv[1], DIR_SWITCH, strlen(DIR_SWITCH))==0) {
            strncpy_s(IniDir, MAX_PATH, argv[2], _MAX_PATH-1);
            sprintf_s(FullpathUrls, _MAX_PATH,"%s\\%s", argv[2], TEST_URLS);
        }
        else {
            Usage(argv[0]);
            exit(1);
        }
    }
/*     else if (argc==1){ */
/*      strcpy_s(IniDir, _MAX_PATH, ".");  */
/*      strcpy_s(FullpathUrls, _MAX_PATH, TEST_URLS); */
/*     } */
    else {
        Usage(argv[0]);
        exit(1);
    }

    IsapiFilterTestSetup(IniDir);

    errorCount = ProcessUrls(FullpathUrls);
    return errorCount;
}
