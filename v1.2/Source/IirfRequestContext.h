// Copyright (c) Microsoft Corporation, 2005, 2006, 2007.  All rights reserved.

#ifndef IIRF_REQUEST_CONTEXT_H
#define IIRF_REQUEST_CONTEXT_H

#include "RewriteRule.h" 

#define IIRF_CONTEXT_MAGIC_NUMBER 0xFADEFEED

typedef struct IirfRequestContext {
    /* dword */ unsigned int Magic;
    char *OriginalUriStem;
    char *QueryString;
    char *RequestMethod;
    char *PhysicalPath;
} IirfRequestContext, *P_IirfRequestContext;


#endif
