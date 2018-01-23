# makefile
#
# for IIRF, Iconic's Isapi Rewriting Filter, v1.6
#
#
# Copyright (c) Dino Chiesa, 2005-2009.  All rights reserved.
#
# This file is released under the License for IIRF.  See the License.txt file 
# for full details. 
#


## Instructions: 
## To use this makefile you may have to change some of the macro definitions, below:

## Set VC8 to the location of Visual-C++ v8. Under $(VC)\bin we should find the cl.exe compiler.
## You can get this with Visual studio 2005, or with Visual-C++ 2005 Express.  
## The default install path is often something like 
##         C:\Program Files\Microsoft Visual Studio 8\VC
## whether you have full Visual Studio install, or an install of
## the Express version.

VC=c:\vc9

## Set PSDK to point to the Windows Platform SDK, the latest version.  The one I use currently is the 
## Windows Server 2003 R2 Platform SDK, available for download at:  
##  http://www.microsoft.com/downloads/details.aspx?FamilyId=0BAF2B35-C656-4969-ACE8-E4C0C0716ADB
## But you can also use the Microsoft Windows Vista SDK, v6.0. 
## (NB:  I haven't tested  binaries produced against the Windows Vista Platform SDK, running on
## Windows Server). 
## The Platform SDK is required for header files and libraries for the binaries.  
## The install location is often $(VC)\PlatformSDK, but not always.  
##

#PSDK=$(VC)\PlatformSDK
#PSDK=C:\Progra~1\MI2578~1\Windows\v6.1
PSDK=C:\Program Files\Microsoft SDKs\Windows\v6.1

## Set CC to the Cl.exe compiler, and set LINK to refer to the linker.  
## This is almost always going to be, $(VC)\bin\cl.exe and $(VC)\bin\link.exe

CC=$(VC)\bin\cl.exe
LINK=$(VC)\bin\link.exe
RC=$(PSDK)\bin\rc.exe

## Set PCRESOURCE to the directory that contains the source
## distribution of PCRE, if you have one. Note: IIRF is built
## against v5.0 of PCRE.  You do not need a source distribution
## of PCRE in order to build IIRF.  All you really need is a
## binary distribution of PCRE: the pcre.h file and the pcre.lib
## static library, which is included in the IIRF distribution.  

PCRE=..\3rdParty

!IFNDEF CONFIG
!ERROR Please define CONFIG with eg, "nmake config=Debug" or "nmake config=Release" 
!ELSEIF "$(CONFIG)" != "Release"  && "$(CONFIG)" != "Debug" 
!MESSAGE config=$(CONFIG)
!ERROR  Define CONFIG with eg, "nmake config=Debug" or "nmake config=Release" 
!ENDIF


BINDIR=.\bin\$(CONFIG)
OBJDIR=.\obj\$(CONFIG)


## set the compiler optimization flags


CSOURCE=.\IsapiRewrite4.c
HSOURCE=RewriteRule.h IirfConfig.h IirfConstants.h IirfRequestContext.h 
OBJS1=$(CSOURCE:.c=.obj)


!IF "$(config)" == "Debug"
CCOPTIONS=/Od /Zi /DEBUG /RTC1 /MTd
LinkOptions=/DEBUG /NODEFAULTLIB:libcmt.lib 
RcOptions=/DDEBUG
OBJS=$(OBJS1:.\=.\obj\Debug\)
!Else
CCOPTIONS=/O2 /Oi /GL /MT
LinkOptions=/LTCG /NODEFAULTLIB:libcmtd.lib 
RcOptions=
OBJS=$(OBJS1:.\=.\obj\Release\)
!Endif

cflags=/W3 /I"$(VC)\Include" /I"$(PSDK)\Include" /I"$(PCRE)"
lflags=/VERBOSE:LIB /SUBSYSTEM:CONSOLE  /LIBPATH:$(VC)\Lib /LIBPATH:"$(PSDK)\Lib" 


## You can set this directory if you want the "install" make target to work.
## Otherwise, ignore it.  If you set this and you run "make install" then it will
## copy the IsapiRewrite4.dll and the ini file into the install directory.
## Handle with care, it can overwrite your ini files!

INSTALL_DIR=c:\Windows\system32\inetsrv\IIRF

## ZIPIT refers to a directory zipping utility that is not included in the IIRF.  Ignore this setting. 

ZIPIT=c:\users\dinoch\bin\backdir.bat

## Version refers to the version of IIRF.  This version string defined here is used only in 
## the names of the zip files created by the ZIPIT tool, therefore you do not need to set it
## if you do not have that tool. 

Version=IonicIsapiRewriter-1.2.16


# =======================================================

all: $(BINDIR)\TestDriver.exe $(BINDIR)\TestParse.exe $(BINDIR)\IsapiRewrite4.dll $(BINDIR)\IirfVersion.exe

$(BINDIR)\IsapiRewrite4.dll: $(CSOURCE) $(HSOURCE) $(PCRE)\pcre.h $(PCRE)\pcre.lib  makefile  $(OBJDIR)\IIRF.res StackWalker.cpp ExceptionHandler.cpp StackWalker.h
        @echo Configuration == $(config) 
        "$(CC)" $(CCOPTIONS) $(cflags)  /EHsc /Fo"$(OBJDIR)\\"  /c  StackWalker.cpp ExceptionHandler.cpp
        "$(CC)" $(CCOPTIONS) $(cflags)        /Fo"$(OBJDIR)\\"  /c  -DPCRE_STATIC  $(CSOURCE)
        if not exist $(BINDIR) (mkdir $(BINDIR))
        "$(LINK)" /out:$@ $(LinkOptions)  /DLL  $(lflags) /DYNAMICBASE /NXCOMPAT /MACHINE:X86 kernel32.lib advapi32.lib $(PCRE)\pcre.lib  /EXPORT:GetFilterVersion /EXPORT:Iirf_GetVersion /EXPORT:HttpFilterProc /EXPORT:IsapiFilterTestSetup /EXPORT:TerminateFilter /EXPORT:EvaluateRules /NODEFAULTLIB:libc  $(OBJS)  $(OBJDIR)\IIRF.res  $(OBJDIR)\StackWalker.obj $(OBJDIR)\ExceptionHandler.obj


$(OBJDIR)\IIRF.res: IIRF.rc makefile
        if not exist $(OBJDIR) (mkdir $(OBJDIR))
        "$(RC)" $(RcOptions) /fo"$@"  /I"$(PSDK)\Include"   /I"$(VC)\Include"  .\IIRF.rc


$(BINDIR)\TestDriver.exe: TestDriver.c RewriteRule.h $(BINDIR)\IsapiRewrite4.dll makefile
        "$(CC)" /c $(CCOPTIONS) $(cflags) /Fo"$(OBJDIR)\\" TestDriver.c 
        "$(LINK)" /out:$@ $(LinkOptions) $(lflags) $(OBJDIR)\TestDriver.obj $(BINDIR)\IsapiRewrite4.lib $(PCRE)\pcre.lib 

$(BINDIR)\IirfVersion.exe: IirfVersion.c RewriteRule.h $(BINDIR)\IsapiRewrite4.dll makefile
        "$(CC)" /c $(CCOPTIONS) $(cflags) /Fo"$(OBJDIR)\\" IirfVersion.c 
        "$(LINK)" /out:$@ $(LinkOptions) $(lflags) $(OBJDIR)\IirfVersion.obj $(BINDIR)\IsapiRewrite4.lib $(PCRE)\pcre.lib 

$(BINDIR)\TestParse.exe: TestParse.c IirfConfig.h $(BINDIR)\IsapiRewrite4.dll makefile
        "$(CC)" /c $(CCOPTIONS) $(cflags) /Fo"$(OBJDIR)\\" TestParse.c 
        "$(LINK)" /out:$@ $(LinkOptions) $(lflags) $(OBJDIR)\TestParse.obj  $(BINDIR)\IsapiRewrite4.lib $(PCRE)\pcre.lib 



install: drop

drop: $(BINDIR)\IsapiRewrite4.dll
        -net stop w3svc
        copy /y  $(BINDIR)\IsapiRewrite4.dll $(INSTALL_DIR)
        if exist $(BINDIR)\IsapiRewrite4.pdb  (copy /y $(BINDIR)\IsapiRewrite4.pdb $(INSTALL_DIR))
        net start w3svc


# $(PCRE)\pcre.h $(PCRE)\pcre.lib: 
#       -mkdir $(PCRE)
#       copy $(PCRESOURCE)\pcre.h $(PCRE)
#       copy $(PCRESOURCE)\pcre.lib $(PCRE)
#       copy $(PCRESOURCE)\Makefile $(PCRE)
#       copy $(PCRESOURCE)\LICENCE $(PCRE)


# Rule for creating ZIP files.
# Note: this will not work for you if you do not have the ZIPIT
# tool

zip: srczip binzip

srczip: $(Version)-$(config)-src.zip

$(Version)-$(config)-src.zip: $(BINDIR)\IsapiRewrite4.dll $(BINDIR)\TestDriver.exe $(BINDIR)\IirfVersion.exe ..\Readme-1.2.txt ..\ReleaseNotes.txt  ..\License.IIRF.txt makefile $(CSOURCE) $(HSOURCE)
        -rd /s /q $(Version)
        mkdir $(Version)
        copy ..\Readme-1.2.txt $(Version)
        copy ..\ReleaseNotes.txt $(Version)
        copy ..\License.IIRF.txt $(Version)
        mkdir $(Version)\Source
        copy makefile $(Version)\Source
        copy IIRF.rc  $(Version)\Source
        copy TestParse.c $(Version)\Source
        copy TestDriver.c $(Version)\Source
        copy IirfVersion.c $(Version)\Source
        copy IirfConstants.h $(Version)\Source
        copy IirfRequestContext.h $(Version)\Source
        copy IirfConfig.h $(Version)\Source
        copy RewriteRule.h $(Version)\Source
        copy IIRF.h $(Version)\Source
        copy IsapiRewrite4.c $(Version)\Source
        mkdir $(Version)\3rdParty
        copy $(PCRE)\License.PCRE.txt $(Version)\License.PCRE.txt
        xcopy /s $(PCRE) $(Version)\3rdParty
        mkdir $(Version)\Source\tests
        xcopy /s tests $(Version)\Source\tests
        mkdir $(Version)\ExampleIni
        xcopy /s ..\ExampleIni $(Version)\ExampleIni

        $(ZIPIT) $(Version) $(Version)-src.zip 
        rd /s /q $(Version)



binzip: $(Version)-$(config)-bin.zip

$(Version)-$(config)-bin.zip: $(BINDIR)\IsapiRewrite4.dll $(BINDIR)\TestDriver.exe $(BINDIR)\TestParse.exe $(BINDIR)\IirfVersion.exe ..\Readme-1.2.txt ..\ReleaseNotes.txt ..\License.IIRF.txt makefile 
        -rd /s /q $(Version)
        mkdir $(Version)
        mkdir $(Version)\lib
        copy $(BINDIR)\IsapiRewrite4.dll $(Version)\lib
        if exist $(BINDIR)\IsapiRewrite4.pdb  (copy $(BINDIR)\IsapiRewrite4.pdb $(Version)\lib)
        mkdir $(Version)\bin
        copy $(BINDIR)\TestDriver.exe $(Version)\bin
        if exist $(BINDIR)\TestDriver.pdb  (copy $(BINDIR)\TestDriver.pdb $(Version)\bin)
        copy $(BINDIR)\TestParse.exe $(Version)\bin
        if exist $(BINDIR)\TestParse.pdb  (copy $(BINDIR)\TestParse.pdb $(Version)\bin)
        copy $(BINDIR)\IirfVersion.exe $(Version)\bin
        if exist $(BINDIR)\IirfVersion.pdb  (copy $(BINDIR)\IirfVersion.pdb $(Version)\bin)
        mkdir $(Version)\tests
        xcopy /s tests $(Version)\tests
        mkdir $(Version)\ExampleIni
        xcopy /s ..\ExampleIni $(Version)\ExampleIni
        copy ..\Readme-1.2.txt $(Version)
        copy ..\ReleaseNotes.txt $(Version)
        copy ..\License.IIRF.txt $(Version)
        copy $(PCRE)\License.PCRE.txt $(Version)

        $(ZIPIT) $(Version) $(Version)-$(config)-bin.zip
        rd /s /q $(Version)


clean: 
        -echo y | rd /s obj
        -echo y | rd /s bin
        if exist vc90.pdb (del vc90.pdb)

tidy: 
        -echo y | rd /s obj

