/*

  Iirf.h

  part of Ionic's Isapi Rewrite Filter [IIRF]

  Copyright (c) Dino Chiesa, 2005-2010.  All rights reserved.

  ==================================================================

  Licensed under the MS Public License.
  http://opensource.org/licenses/ms-pl.html

  or, see Rewriter.c for the details of the license.

  Last saved:
  Time-stamp: <2010-May-29 21:27:38>

*/


#ifndef IIRF_H
#define IIRF_H


#include "IirfConfig.h"
#include "IirfConstants.h"
#include "IirfRequestContext.h"

#include "debugger.h"


#ifdef _WIN64
extern DWORD Iirf_ConvertSizeTo32bitsImpl(size_t sz, char *file, int line);
#define Iirf_ConvertSizeTo32bits(expr) Iirf_ConvertSizeTo32bitsImpl(expr, __FILE__, __LINE__)
#else
#define Iirf_ConvertSizeTo32bits(expr) (DWORD)(expr)
#endif

#endif // IIRF_H
