/*

  ExceptionHandler.cpp

  part of Ionic's Isapi Rewrite Filter [IIRF]

  Copyright (c) Dino Chiesa, 2005-2011.  All rights reserved.

  ==================================================================

  Licensed under the MS Public License.
  http://opensource.org/licenses/ms-pl.html

  See the attached License.txt file, or see the Rewriter.c module for
  the details of the license for IIRF.

  Last saved: <2011-September-11 18:05:38>

*/

#include <windows.h>
#include <tchar.h>
#include <stdio.h>

#include "StackWalker.h"

#include "Iirf.h"


extern "C" void LogMessage( IirfVdirConfig * cfg, int MsgLevel, char * format, ... );
extern "C" IirfServerConfig * gFilterConfig;

// Simple implementation of an additional output to the console:
class MyLoggingStackWalker : public StackWalker
{
private:
    IirfVdirConfig * sitecfg;

public:
    MyLoggingStackWalker(IirfVdirConfig * cfg) : StackWalker()
        {
            char drive[_MAX_DRIVE];
            char dir[_MAX_DIR];
            sitecfg = cfg;

            // add the directory for the DLL, to the search path for PDB files
            this->m_szSymPath = (LPSTR) malloc(_MAX_PATH);
            _splitpath_s(gFilterConfig->DllLocation, drive, _MAX_DRIVE, dir, _MAX_DIR, NULL, 0, NULL, 0);
            _makepath_s(this->m_szSymPath, _MAX_PATH, drive, dir, NULL, NULL);
        }
    virtual void OnOutput(LPCSTR szText)
        {
            if (sitecfg)
                LogMessage(sitecfg, 0, (char*)szText);
            StackWalker::OnOutput(szText);
        }

    // suppress output for OnLoadModule, unless LogLevel is really high
    virtual void OnLoadModule(LPCSTR img, LPCSTR mod, DWORD64 baseAddr, DWORD size, DWORD result, LPCSTR symType, LPCSTR pdbName, ULONGLONG fileVersion)
        {
            if (sitecfg && (sitecfg->LogLevel > 5))
                StackWalker::OnLoadModule(img, mod, baseAddr, size, result, symType, pdbName, fileVersion);
        }

};




extern "C" int ExceptionFilter(EXCEPTION_POINTERS *pExp, IirfVdirConfig * cfg)
{
    MyLoggingStackWalker *sw = new MyLoggingStackWalker(cfg);
    LogMessage(cfg, 0, (char*)"EXCEPTION");
    sw->ShowCallstack(GetCurrentThread(), pExp->ContextRecord);
    //return EXCEPTION_EXECUTE_HANDLER;
    return EXCEPTION_CONTINUE_SEARCH;  // allow the process to crash
}

