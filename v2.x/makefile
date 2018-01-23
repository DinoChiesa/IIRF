# makefile
#
# for IIRF v2.x, Iconic's Isapi Rewriting Filter.

# This makefile will build IIRF for x86 and x64, as well as the IIRF
# tools like TestDriver and TestParse.  It is maintained independently
# of, and in parallel to, the IIRF.sln file that can be used in Visual
# Studio.  Either can be used to build IIRF.
#
#
# Copyright (c) Dino Chiesa, 2005-2011.  All rights reserved.
#
# This file is released under the License for IIRF.  See the License.txt file
# for full details.
#

## Instructions:
## To use this makefile you may have to change some of the macro definitions, below.

## Set VC to the location of Visual-C++ v8, v9, or v10. Under $(VC)\bin we should find the
## cl.exe compiler.
## You can get this with Visual Studio 2005 or 2008, with Visual-C++ 2005 or 2008 Express,
## or with the Windows SDK, which now includes the VC++ compiler.
## The default install path is often something like
##         C:\Program Files\Microsoft Visual Studio 8\VC
##         C:\Program Files\Microsoft Visual Studio 9\VC
##                 -or-
##         C:\Program Files\Microsoft Visual Studio 10\VC
## ...regardless what installation vehicle you used to get the compiler.
##
VC=c:\vc10

# You may also need <VS>\Common7\IDE on the path, where VS is one of
# VS8, 9, or 10, in order to get mspdb{80,90,100}.dll , which I guess is
# required by the cl.exe compiler.

## Set PSDK to point to the location of the Windows SDK, the latest version.
## This used to be called the "Platform SDK"
## I have successfully used these Windows SDKs in building IIRF:
##  - the Windows Server 2003 R2 Platform SDK
##  - the Windows Vista SDK, v6.0.
##  - the Windows Vista SDK SP1, v6.1.
##  - the Windows 7 SDK, v7.0.
##
## In the SDK, you specifically need the IIS SDK files.
##
## The Windows SDK is required for header files and libraries for the
## binaries.  The install location on disk is often c:\program
## files\Microsoft SDKs\Windows\<VERSION> , where <VERSION> is v6.0,
## v6.1, v7.0, etc.  I often use the junction.exe utility available in
## the sysinternals suite
## (http://technet.microsoft.com/en-us/sysinternals/default.aspx) to
## create a junction at c:\windowsSDK.
##

#PSDK=c:\WindowsSDK
#PSDK=C:\Progra~1\MI2578~1\Windows\v6.1
#PSDK=C:\Program Files\Microsoft SDKs\Windows\v6.1
PSDK=C:\Program Files\Microsoft SDKs\Windows\v7.0




## Set PCRE to the directory that contains the binary build products for
## PCRE. Note: IIRF is built against v8.0 of PCRE, but will build
## against v7.6, 8.0, and 8.11, and probably others.  You do not need a
## source distribution of PCRE in order to build IIRF.  All you need is
## a binary distribution of PCRE: the pcre.h file and the pcre.lib
## static library.  These are included in the IIRF distribution. If you
## do want to build PCRE yourself, see the Readme file in the 3rdParty
## directory in the source distribution of IIRF.

PCRE=3rdParty


!IFNDEF CONFIG
!ERROR Please define CONFIG with eg, "nmake CONFIG=Debug" or "nmake CONFIG=Release"
!ELSEIF "$(CONFIG)" != "Release"  && "$(CONFIG)" != "Debug"
!MESSAGE CONFIG=$(CONFIG)
!ERROR  Define CONFIG with eg, "nmake CONFIG=Debug" or "nmake CONFIG=Release"
!ENDIF


!IFNDEF PLATFORM
!MESSAGE Defining PLATFORM to x86
PLATFORM=x86
!ELSEIF "$(PLATFORM)" != "x86"  && "$(PLATFORM)" != "x64"
!MESSAGE PLATFORM=$(PLATFORM)
!ERROR  Define PLATFORM with eg, "nmake PLATFORM=x86" or "nmake PLATFORM=x64"
!ENDIF


BINDIR=bin\$(PLATFORM)\$(CONFIG)
OBJDIR=obj\$(PLATFORM)\$(CONFIG)


CSOURCE=.\Filter\Rewriter.c .\Filter\Proxy.c .\Filter\UrlDecoder.c .\Filter\Extension.c .\Filter\Utils.c .\Filter\IIrfConfig.c .\Filter\IirfLogging.c
HSOURCE=Filter\RewriteRule.h Filter\IirfConfig.h Filter\IirfConstants.h Filter\IirfRequestContext.h Filter\Iirf.h Filter\debugger.h
OBJS1=$(CSOURCE:.c=.obj)
EXPORTS=/EXPORT:GetFilterVersion /EXPORT:HttpFilterProc /EXPORT:TerminateFilter \
       /EXPORT:GetExtensionVersion /EXPORT:HttpExtensionProc /EXPORT:TerminateExtension \
       /EXPORT:Iirf_EvaluateRules /EXPORT:Iirf_IsapiFilterTestSetup \
       /EXPORT:Iirf_GetVersion \
       /EXPORT:LogMessage /EXPORT:Iirf_GetBuildSig



## set the compiler optimization flags

!IF "$(CONFIG)" == "Debug"
CCOPTIONS=/Od  /Zi /DEBUG /RTC1 /MTd
AddlLinkOptions=/DEBUG /NODEFAULTLIB:libcmt.lib
RcOptions=/DDEBUG
!IF "$(PLATFORM)" == "x86"
OBJS=$(OBJS1:.\Filter=.\Filter\obj\x86\Debug)
!Else
OBJS=$(OBJS1:.\Filter=.\Filter\obj\x64\Debug)
!Endif
!Else
CCOPTIONS=/O2 /Oi /GL /MT
AddlLinkOptions=/LTCG /NODEFAULTLIB:libcmtd.lib
RcOptions=
!IF "$(PLATFORM)" == "x86"
OBJS=$(OBJS1:.\Filter=.\Filter\obj\x86\Release)
!Else
OBJS=$(OBJS1:.\Filter=.\Filter\obj\x64\Release)
!Endif
!Endif


RC=$(PSDK)\bin\rc.exe
LinkOptions=/incremental:no /NODEFAULTLIB:MSVCRT.lib /NODEFAULTLIB:MSVCRTd.lib  $(AddlLinkOptions)

## Set CC to the Cl.exe compiler, and set LINK to refer to the linker.
## This is almost always going to be, $(VC)\bin\cl.exe and $(VC)\bin\link.exe

!IF "$(PLATFORM)" == "x86"
CC=$(VC)\bin\cl.exe
LINK=$(VC)\bin\link.exe
lflags=/VERBOSE:LIB /SUBSYSTEM:CONSOLE  /LIBPATH:"$(VC)\Lib" /LIBPATH:"$(PSDK)\Lib" /MACHINE:X86
!Else
CC=$(VC)\bin\amd64\cl.exe
LINK=$(VC)\bin\amd64\link.exe
lflags=/VERBOSE:LIB /SUBSYSTEM:CONSOLE  /LIBPATH:"$(VC)\Lib\amd64" /LIBPATH:"$(PSDK)\Lib\x64" /MACHINE:X64
EXPORTS=$(EXPORTS) /EXPORT:Iirf_ConvertSizeTo32bitsImpl
!Endif


cflags=/W3 /I"$(VC)\Include" /I"$(PSDK)\Include" /I"$(PCRE)"


## You can set this directory if you want the "install" and "drop" make targets to work.
INSTALL_DIR=c:\Windows\system32\inetsrv\IIRF


# =======================================================

# the default build target
help:
        @echo.
        @echo.
        @echo Define the build type, platform, and target on the nmake command line, eg,
        @echo "nmake PLATFORM=x86 CONFIG=Debug all"
        @echo.    or
        @echo "nmake PLATFORM=x64 CONFIG=Release filter"
        @echo.    etc


all: binaries setup

binaries: $(BINDIR)\TestDriver.exe $(BINDIR)\TestParse.exe $(BINDIR)\Iirf.dll $(BINDIR)\IirfVersion.exe  $(BINDIR)\UrlDecoder.exe

filter: $(BINDIR)\Iirf.dll

Version: $(BINDIR)\IirfVersion.exe

setup: binaries
        if $(CONFIG)==Release (if exist bin\$(PLATFORM)\Release\IIRF.dll ( cd Setup && nmake /nologo $(PLATFORM) && cd .. ))

$(BINDIR):
        if not exist $(BINDIR) (mkdir $(BINDIR))

$(PCRE)\pcre.h: $(PCRE)\$(PLATFORM)\pcre.h
        copy $(PCRE)\$(PLATFORM)\pcre.h  $(PCRE)\pcre.h

$(BINDIR)\Iirf.dll: $(BINDIR) $(CSOURCE) $(HSOURCE) $(PCRE)\pcre.h $(PCRE)\$(PLATFORM)\pcre.lib  makefile  Filter\$(OBJDIR)\IIRF.res Filter\StackWalker.cpp Filter\StackWalker.h Filter\ExceptionHandler.cpp
        @echo Configuration == $(CONFIG)   Platform == $(PLATFORM)
        "$(CC)" $(CCOPTIONS) $(cflags)  /EHsc /Fo"Filter\$(OBJDIR)\\"  /c  Filter\StackWalker.cpp Filter\ExceptionHandler.cpp
        "$(CC)" $(CCOPTIONS) $(cflags)        /Fo"Filter\$(OBJDIR)\\"  /c  -DPCRE_STATIC  $(CSOURCE)
        "$(LINK)" /out:$@ $(LinkOptions)  /DLL  $(lflags)  /DYNAMICBASE /NXCOMPAT kernel32.lib  Advapi32.lib shlwapi.lib WinHttp.lib  "$(PCRE)\$(PLATFORM)\pcre.lib"  $(EXPORTS) /NODEFAULTLIB:libc $(OBJS) .\Filter\$(OBJDIR)\IIRF.res .\Filter\$(OBJDIR)\StackWalker.obj .\Filter\$(OBJDIR)\ExceptionHandler.obj


Filter\$(OBJDIR)\IIRF.res: Filter\IIRF.rc makefile
        if not exist Filter\$(OBJDIR) (mkdir Filter\$(OBJDIR))
        "$(RC)" $(RcOptions) /fo"$@"  /I"$(PSDK)\Include"    /I"$(VC)\Include"   .\Filter\IIRF.rc


$(BINDIR)\TestDriver.exe: TestDriver\TestDriver.c Filter\RewriteRule.h $(BINDIR)\Iirf.dll makefile
        if not exist TestDriver\$(OBJDIR) (mkdir TestDriver\$(OBJDIR))
        "$(CC)" /c $(CCOPTIONS) $(cflags) /Fo"TestDriver\$(OBJDIR)\\"  -I Filter TestDriver\TestDriver.c
        "$(LINK)" /out:$@ $(LinkOptions) $(lflags) .\TestDriver\$(OBJDIR)\TestDriver.obj  $(BINDIR)\Iirf.lib  WinHttp.lib


$(BINDIR)\IirfVersion.exe: Version\IirfVersion.c Filter\RewriteRule.h $(BINDIR)\Iirf.dll makefile
        @echo BINDIR = $(BINDIR)
        if not exist Version\$(OBJDIR) (mkdir Version\$(OBJDIR))
        "$(CC)" /c $(CCOPTIONS) $(cflags) /Fo"Version\$(OBJDIR)\\"   -I Filter Version\IirfVersion.c
        "$(LINK)" /out:$@ $(LinkOptions) $(lflags)  .\Version\$(OBJDIR)\IirfVersion.obj $(BINDIR)\Iirf.lib "$(PCRE)\$(PLATFORM)\pcre.lib"


$(BINDIR)\TestParse.exe: TestParse\TestParse.c Filter\IirfConfig.h $(BINDIR)\Iirf.dll makefile
        if not exist TestParse\$(OBJDIR) (mkdir TestParse\$(OBJDIR))
        "$(CC)" /c $(CCOPTIONS) $(cflags) /Fo"TestParse\$(OBJDIR)\\"  -I Filter TestParse\TestParse.c
        "$(LINK)" /out:$@ $(LinkOptions) $(lflags) .\TestParse\$(OBJDIR)\TestParse.obj  $(BINDIR)\Iirf.lib


$(BINDIR)\UrlDecoder.exe: Filter\UrlDecoder.c makefile
        "$(CC)" $(CCOPTIONS) $(cflags) /DURLDECODE_STANDALONE  Filter\UrlDecoder.c  -link $(LinkOptions) /out:$@ $(lflags)
        if exist UrlDecoder.obj (del UrlDecoder.obj)



install: drop

drop: $(BINDIR)\IIRF.dll
        -net stop w3svc
        if not exist $(INSTALL_DIR)  (mkdir $(INSTALL_DIR))
        copy /y  $(BINDIR)\IIRF.dll $(INSTALL_DIR)
        if exist $(BINDIR)\IIRF.pdb  (copy /y $(BINDIR)\IIRF.pdb $(INSTALL_DIR))
        net start w3svc


tidy:
        -echo y | rd /s Filter\obj
        -echo y | rd /s Version\obj
        -echo y | rd /s TestDriver\obj
        -echo y | rd /s TestParse\obj

clean: tidy
        -echo y | rd /s bin
        -echo y | rd /s Setup\out
        if exist vc90.pdb (del vc90.pdb)
        if exist vc100.pdb (del vc100.pdb)
