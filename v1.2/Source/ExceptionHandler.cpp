/*
  ExceptionHandler.cpp
  
  part of Ionic's Isapi Rewrite Filter [IIRF]

  ISAPI Filter that does  URL-rewriting. 
  Inspired by Apache's mod_rewrite .
  Implemented in C, does not use MFC. 

  Copyright (c) Dino Chiesa, 2009.  All rights reserved.

  ==================================================================

 */

#include <windows.h>
#include <tchar.h>
#include <stdio.h>

#include "StackWalker.h"

#include "Iirf.h"


extern "C" void LogMessage(int MsgLevel, char * format, ... );
extern "C" char IniFileDirectory[];
extern "C" IirfConfig * config;


// Simple implementation of an additional output to the logfile
class MyLoggingStackWalker : public StackWalker
{
    
public:
    MyLoggingStackWalker() : StackWalker()
        {
            // add the directory for the DLL, to the search path for PDB files
            this->m_szSymPath = (LPSTR) _strdup(IniFileDirectory);
        }
    
    virtual void OnOutput(LPCSTR szText)
        {
            LogMessage( 0, (char*)szText);
            StackWalker::OnOutput(szText);
        }

    // suppress output for OnLoadModule, unless LogLevel is really high
    virtual void OnLoadModule(LPCSTR img, LPCSTR mod, DWORD64 baseAddr, DWORD size, DWORD result, LPCSTR symType, LPCSTR pdbName, ULONGLONG fileVersion)
        {
            if (config->LogLevel > 5) 
                StackWalker::OnLoadModule(img, mod, baseAddr, size, result, symType, pdbName, fileVersion);
        }
    
};




extern "C" int ExcFilter(EXCEPTION_POINTERS *pExp)
{
    MyLoggingStackWalker *sw = new MyLoggingStackWalker();
    LogMessage(0, (char*)"EXCEPTION");
    sw->ShowCallstack(GetCurrentThread(), pExp->ContextRecord);
    //return EXCEPTION_EXECUTE_HANDLER;
    return EXCEPTION_CONTINUE_SEARCH;  // allow the process to crash
}

