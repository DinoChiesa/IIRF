/*

  IirfRequestContext.h

  part of Ionic's Isapi Rewrite Filter [IIRF]

  Copyright (c) Dino Chiesa, 2005-2010.  All rights reserved.

  ==================================================================

  Licensed under the MS Public License.
  http://opensource.org/licenses/ms-pl.html

  or, see Rewriter.c for the details of the license.

  Last saved:
  Time-stamp: <2011-May-02 13:48:31>

*/


#ifndef IIRF_REQUEST_CONTEXT_H
#define IIRF_REQUEST_CONTEXT_H

#include "IirfConfig.h"
#include <HttpFilt.h> // HTTP_FILTER_AUTH_COMPLETE_INFO

#define IIRF_CONTEXT_MAGIC_NUMBER 0xFADEFEED

typedef struct IirfRequestContext {
    unsigned int Magic;
    char *OriginalUriStem;
    char *QueryString;
    char *RequestUri;
    char *RequestMethod;
    char *PhysicalPath;
    boolean RecordOriginalUri;
    HTTP_FILTER_AUTH_COMPLETE_INFO * AuthCompleteInfo;
    char *InterimUrl;
    char *InterimMethod;
    IirfVdirConfig *VdirConfig;
} IirfRequestContext, *P_IirfRequestContext;



// structs
typedef struct _IirfRequestHeader {
    char *S[2]; // array of two char *
    struct _IirfRequestHeader *Next;
} IirfRequestHeader;



#endif
