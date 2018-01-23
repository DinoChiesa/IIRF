# win32 makefile for nmake
#
# for PCRE, the Perl-Compatible regular expression library
# See http://www.pcre.org
#
# Disclaimer: 
# this worked for me, may not work for you! 
# Works with PCRE v5.0 . 
#
# To use this thing:
# - download PCRE v5.0 (or later?) 
# - copy this makefile into the PCRE dir. 
# - modify the settings for VC7 and PSDK
# - run nmake!
# 
# =======================================================
# Ionic Shade
# Thu, 06 Jan 2005  10:10
#


PCRE_SOURCES = \
  pcre_compile.c \
  pcre_config.c \
  pcre_dfa_exec.c \
  pcre_exec.c \
  pcre_fullinfo.c \
  pcre_get.c \
  pcre_globals.c \
  pcre_info.c \
  pcre_maketables.c \
  pcre_newline.c \
  pcre_ord2utf8.c \
  pcre_refcount.c \
  pcre_study.c \
  pcre_tables.c \
  pcre_try_flipped.c \
  pcre_ucp_searchfuncs.c \
  pcre_valid_utf8.c \
  pcre_version.c \
  pcre_xclass.c \
  pcre_chartables.c


PCRE_OBJ = $(PCRE_SOURCES:.c=.obj)


PCRE_HEADERS= \
  pcre_internal.h \
  ucp.h \
  ucpinternal.h \
  ucptable.h


#VC=c:\vs.net\Vc7
VC=c:\vc8
PSDK=C:\Progra~1\MI2578~1\Windows\v6.0
#PSDK=$(VC7)\PlatformSDK
CC=$(VC)\bin\cl.exe
LIB=$(VC)\bin\lib.exe

CCOPTS= -DHAVE_CONFIG_H  /I$(VC)\Include /I$(PSDK)\Include

# =======================================================

all: pcre pcretest

pcre: pcre.dll pcre.lib pcreposix.lib

pcretest: pcretest.exe

dftables.exe: dftables.c
	$(CC) $(CCOPTS) -DSUPPORT_UTF8    dftables.c -link /LIBPATH:$(VC)\Lib /LIBPATH:$(PSDK)\Lib  

pcre_chartables.c: dftables.exe
	dftables.exe pcre_chartables.c

#static library
pcre.lib: pcre_chartables.c $(PCRE_SOURCES)  makefile
	$(CC) $(CCOPTS)  -DSTATIC -DSUPPORT_UTF8 -DPOSIX_MALLOC_THRESHOLD=10 /c $(PCRE_SOURCES)
	$(LIB) /OUT:pcre.lib $(PCRE_OBJ) /VERBOSE:LIB /NODEFAULTLIB /NODEFAULTLIB:libc.lib

pcreposix.lib: pcre_chartables.c makefile
	$(CC) $(CCOPTS)  -DPCRE_STATIC  -DSUPPORT_UTF8 -DPOSIX_MALLOC_THRESHOLD=10 /c pcreposix.c
	$(LIB) /OUT:pcreposix.lib pcreposix.obj

#dynamic library
pcre.dll: $(PCRE_SOURCES) makefile
	$(CC) $(CCOPTS) -DSUPPORT_UTF8 -DPOSIX_MALLOC_THRESHOLD=10 /LDd  $(PCRE_SOURCES) /Fepcre.dll  /link /verbose:LIB /implib:pcre-tmp.lib /LIBPATH:$(VC)\Lib /LIBPATH:$(PSDK)\Lib  /SUBSYSTEM:CONSOLE  /DEBUG  /EXPORT:pcre_compile /EXPORT:pcre_fullinfo  /EXPORT:pcre_exec   /EXPORT:pcre_version    /EXPORT:pcre_config


pcreposix.dll: pcre_chartables.c makefile
	$(CC) $(CCOPTS) -DSUPPORT_UTF8 -DPOSIX_MALLOC_THRESHOLD=10 /LDd pcreposix.c /Fepcreposix.dll  /link /LIBPATH:$(VC)\Lib /LIBPATH:$(PSDK)\Lib  /SUBSYSTEM:CONSOLE  /DEBUG 


pcretest.exe: pcretest.c pcre.lib pcreposix.lib
	$(CC) $(CCOPTS) -DPCRE_STATIC -DSUPPORT_UTF8 pcretest.c pcre.lib pcreposix.lib /link /LIBPATH:$(VC)\Lib /LIBPATH:$(PSDK)\Lib  /SUBSYSTEM:CONSOLE  /DEBUG



# =======================================================

clean:
	-del pcre.dll
	-del pcre.lib
	-del pcreposix.lib
	-del pcreposix.dll
	-del pcretest.exe

