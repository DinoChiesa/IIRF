#ifndef _DEBUGGER_H
#define _DEBUGGER_H

// An un-catchable DebugBreak.
//
// for more info:
// http://www.codeproject.com/KB/debug/DebugBreakAnyway.aspx

#define DebugBreakAnyway()    \
    PreDebugBreakAnyway();    \
    DebugBreak();


extern void __stdcall PreDebugBreakAnyway(void);

#endif
