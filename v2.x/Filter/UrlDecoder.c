
/*
 * UrlDecoder.c
 *
 * URL-Decoder logic.  This is part of IIRF and is licensed
 * as such.  See the License.IIRF.txt file for details.
 *
 * This is compiled into the ISAPI Filter but can also be compiled
 * as a standalone test program, if you define the symbol
 * URLDECODE_STANDALONE on the compile line:
 *
 *   c:\vc9\bin\cl.exe /Zi /O2 /Oi /GL /DURLDECODE_STANDALONE=1
 *         -Ic:\vc9\Include
 *         -I "C:\Program Files\Microsoft SDKs\Windows\v6.1\Include"
 *          Filter\UrlDecoder.c
 *          -link /LTCG /out:out\Release\UrlDecoder.exe
 *          /SUBSYSTEM:CONSOLE
 *          /LIBPATH:c:\vc9\Lib
 *          /LIBPATH:"C:\Program Files\Microsoft SDKs\Windows\v6.1\Lib"
 *
 * Author:  Dinoch
 * Created:  Wed Jul 30 12:13:14 2008
 *
 * Last saved in emacs:
 * Time-stamp: <2011-February-19 09:32:12>
 * ------------------------------------------------------------------
 *
 * Copyright (c) Dino Chiesa 2008-2011.  All rights reserved.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>


#include <WTypes.h>     // for ?



typedef struct _CharToEncode {
    unsigned char c;
    char encoded[4];
} CharToEncode;


CharToEncode gUrlEncodedChars[186];  // 22



void Initialize_SetOneChar(unsigned char c, int ix)
{
    gUrlEncodedChars[ix].c= c;
    sprintf_s(gUrlEncodedChars[ix].encoded, 4, "%%%02X", c);
    //printf("%3d: '%c' ==> %s\n",ix, gUrlEncodedChars[ix].c, gUrlEncodedChars[ix].encoded);
}


void InitializeUrlDecoder()
{
    char startRange[]= "%=\"<>\\^[]`+$,@:;/!#?&'";
    int i,j;
    int len = (int)strlen(startRange);
    int max = sizeof(gUrlEncodedChars)/sizeof(gUrlEncodedChars[0]);
    for(i = 0; i < len && i < max; i++)
        Initialize_SetOneChar(startRange[i], i);

    for(j = 1; j < 33 && i < max; j++, i++)
        Initialize_SetOneChar(j, i);

    for(j = 124; j < 256 && i < max; j++, i++)
        Initialize_SetOneChar(j, i);
}



// UrlDecode - url-decode a string.
// The result is the same or smaller than the original string.
//
// Always allocates a new string, whether there is any
// decoding or not.
//
char * UrlDecode(char * encoded)
{
    int i;
    size_t j, j2;
    char * decoded = _strdup(encoded);
    size_t len= strlen(encoded);
    int replaced= 0;
    int N = sizeof(gUrlEncodedChars)/sizeof(gUrlEncodedChars[0]);

    for (j=0, j2=0; j < len; j++, j2++) {
        replaced= 0;
        if (decoded[j]=='%' && (j==0 || decoded[j-1]!='%') && j+2 < len ) {
            int c = decoded[j+3];
            decoded[j+3]= '\0';

            for (i=0; i < N && replaced==0; i++) {
                if (_strnicmp(decoded+j, gUrlEncodedChars[i].encoded, 3)==0) {
                    decoded[j2]= gUrlEncodedChars[i].c;
                    replaced=1;
                }
            }

            decoded[3+j]= c;
        }

        if (replaced==0) {
            if (j!=j2)
                decoded[j2]= decoded[j];
        }
        else
            j+=2;
    }
    decoded[j2]='\0';

    return decoded;
}


// char * UrlEncodeOneChar(char c)
// {
//     static int N = sizeof(gUrlEncodedChars)/sizeof(gUrlEncodedChars[0]);
//     int i;
//     for (i=0; i < N && replaced==0; i++) {
//         if (c==gUrlEncodedChars[i].c)
//             return gUrlEncodedChars[i].encoded;
//     }
//     return NULL;
// }



/*
 * UrlEncode
 *
 * Purpose:
 *
 *   Url encode a string.
 *
 * Arguments:
 *
 *   decoded - char * - the input string.
 *
 * Returns:
 *
 *   char * - an allocated pointer to a new string. The new string
 *            is the same length or longer than the original string.
 *            The caller must free it.
 *
 */
char * UrlEncode(char * decoded)
{
    char * encoded = NULL;
    size_t j, j2;
    size_t szOut = 0;
    size_t len= strlen(decoded);
    int i,k;
    int pass;
    int replaced= 0;
    int N = sizeof(gUrlEncodedChars)/sizeof(gUrlEncodedChars[0]);
    int X = sizeof(gUrlEncodedChars[0].encoded)/sizeof(gUrlEncodedChars[0].encoded[0]);

    for (pass=0; pass < 2; pass++) {
        // first pass to count and allocate, 2nd pass to cpoy
        for (j=0, j2=0; j < len; j++) {
            replaced= 0;
            // for each encodable char
            for (i=0; i < N && replaced==0; i++) {
                if (decoded[j]==gUrlEncodedChars[i].c) {
                    if (pass==0) {
                        szOut+= X;
                    }
                    else {
                        for (k=0; k < X && j2 < szOut; k++)
                            encoded[j2++]= gUrlEncodedChars[i].encoded[k];
                        j2--; // back up one
                    }
                    replaced=1;
                }
            }

            if (replaced==0) {
                if (pass==0) {
                    szOut++;
                }
                else {
                    encoded[j2++]= decoded[j];
                }
            }
        }

        if (pass==0) {
            //szOut+= 5; // "http" + terminator
            //printf("allocating %d bytes\n", szOut);
            encoded = (char*) malloc(szOut);
            // // skip over http://
            // for (j=0, j2=0; j < 5; j++, j2++)
            //     encoded[j2] = decoded[j];
        }
    }

    encoded[j2]='\0';

    return encoded;
}





#if URLDECODE_STANDALONE

void Dump()
{
    int i;
    for (i=0; i < sizeof(gUrlEncodedChars)/sizeof(gUrlEncodedChars[0]); i++) {
        printf("'%c' ==> %s\n",gUrlEncodedChars[i].c, gUrlEncodedChars[i].encoded);
    }
}


void Usage(char *appname)
{
    printf("\nUrlDecoder.exe\n");
    printf("  Decodes URLs that include %% escape sequences, or Encodes URLs to\n"
           "  use escape sequences where appropriate. Use this to test and verify\n"
           "  the URLs you construct.\n\n"
           "  This tool is part of IIRF v2.0.\n\n");
    printf("usage:\n");
    printf("  %s [-d|-e] <url> [ [-d|-e] <url>...]\n\n", appname);
}



int main(int argc, char **argv)
{
    int i;
    boolean wantDecode = TRUE;
    if (argc<2) {
        Usage(argv[0]);
        exit(1);
    }

    printf("Decoding URLs...\n");
    InitializeUrlDecoder();

    for (i=1; i < argc; i++) {
        if (_strnicmp(argv[i], "-e", strlen("-e"))==0) {
            wantDecode = FALSE;
        }
        else if (_strnicmp(argv[i], "-d", strlen("-d"))==0) {
            wantDecode = TRUE;
        }
        else {
            char * result= NULL;
            printf("before: %s\n", argv[i]);
            if (wantDecode) {
                UrlDecode(argv[i]);
                result = argv[i];
            }
            else {
                result = UrlEncode(argv[i]);

            }
            printf("after : %s\n\n", result);
            if (result!= argv[i]) {
                free(result);
            }
        }
    }
}

#endif
