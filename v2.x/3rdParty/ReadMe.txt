Attention

This directory contains Third Party code,
specifically the PCRE library.

IIRF depends on PCRE.

The binary IIRF release statically links to the PCRE library.
The source IIRF release ships the static PCRE library.

PCRE is available under a distinct license from that
for IIRF.

Learn more about PCRE at http://www.pcre.org

==================================================================
Tue, 06 Apr 2010  08:50

To build PCRE v8.02 from source, for use with IIRF, for x86 platform:

Pre-requisites: cmake.

Get cmake from http://www.cmake.org.

CMake is a makefile configurator.  It generates makefiles for use by
various make utilities.  One of the kinds of makefiles it generates is
Visual Studio solution and .vcproj files.  Use cmake to build
a VS2008-compatible SLN for PCRE.


1. put cmake on path

2. extract PCRE source to c:\pcre-8.02\src

3. create a build dir:  c:\pcre-8.02\build-x86

4. run cmake-gui.exe

5. Specify locations of src + build from steps 2 & 3 above

6. Click "Configure"

7. Click the "Advanced" button.

    - Change all /MD to MT and /MDd to MTd .
    - remove all the standard libraries  (kernel32.lib, shell32.lib,
      etc.  all are unnecessary for PCRE)

8. Click "Configure" again

9. Click "Generate"

10. exit cmake, go to the build directory, run:

    msbuild PCRE.SLN /p:Configuration=Release

    Find the build products in the Release directory

done.


Then copy these files to the 3rdparty dir for IIRF:

    build\pcre.h
    build\Release\pcre.lib



==================================================================
Mon, 03 Jan 2011  15:22

Update.
Building PCRE v8.11 from source, for use with IIRF, for the x64 platform.


1. download cmake from www.cmake.org, and extract it.

2. open a command prompt window (cmd.exe)

3. put the cmake bin directory on your path. Assuming you extracted
   cmake to c:\cmake, then from within the command prompt do this:

     set path=%path%;c:\cmake\bin

4. Ensure you have the latest Windows SDK.  This is a free download
   from Microsoft.  See
   http://msdn.microsoft.com/en-us/windows/bb980924.aspx

   Put the winsdk bin directory on your path.  To do so, from within the
   command prompt window, do this:

       set path=%path%;c:\winsdk\bin

   (the above assumes you have created a junction called \winsdk that
   points to the Windows SDK install directory, typically something like
   C:\Program Files\Microsoft SDKs\Windows\v7.0 )

5. Ensure you have the MS VC 2008 or 2010 compiler.  This is available
   as a free download from Microsoft via the VC++ 2008 or 2010 Express
   tool. See http://www.microsoft.com/express .  You can also use the
   VC++ compiler that is installed with a commercial version of Visual
   Studio 2010 or 2008.

   Note: The 64-bit compiler is generally NOT installed with VC++
   Express. To get the 64-bit compiler, you must install the Windows SDK
   *after* you install VC++ Express.

   Make sure the cl.exe compiler for the x64 platform is available via
   the path.  From within the command prompt window, do this:

   (for visual Studio 2008)
       set PATH=%PATH%;c:\vc9\bin\amd64

   (for visual Studio 2010)
       set PATH=%PATH%;c:\vc10\bin\amd64

   (the above assumes you have created a junction called \vc9 that
   points to the Visual C++ 2008 install directory, typically something
   like C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC , or
   that you have a junction called \vc10 that points to the Visual C++
   2010 install directory, something like
   C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC .

   This gives you the VC++ compiler that can run on x86 and produice x64
   object code.  Because it runs on one hardware platform and generates
   code for another, it is considered to be a cross-compiler.

   To compile for x64, you must not use the \vc9\bin\cl.exe compiler. It
   will produce only x86 object code, which is not what you want.

   Also set the INCLUDE and LIB environment variables in the same
   command prompt:

       set LIB=c:\vc9\lib\amd64;c:\winsdk\Lib\x64
       set INCLUDE=c:\vc9\include;c:\winsdk\include

   Replace vc9 in the above with vc10, if you are using the 2010 version
   of the Visual Studio tools.


6. download PCRE v8.11 source from http://www.pcre.org, extract it to
   a directory, such as  c:\pcre\pcre-8.11

   In my case I created a junction called "src" pointing to that
   directory,  so the source directory I used was:  c:\pcre\src

7. create a build dir:  c:\pcre\build-x64

8. From the command prompt, run cmake-gui.exe

   Specify locations of src + build from steps 6 & 7 above.

   Click the "Configure" button.

   If everything goes well, the new options will be displayed in red in
   the cmake window.

9. Click the "Advanced" checkbox.

    - Change all /MD to MT and /MDd to MTd .
    - remove all the standard libraries  (kernel32.lib, shell32.lib,
      etc.  all are unnecessary for PCRE)

   Click "Configure" again.

   If things don't go well, you may get messages about:

    - a missing cl.exe

      in this case, check your path, verify that the \vc9\bin\amd64
      directory is on your path.  Or \vc10\bin\amd64, if using the 2010
      version of the tools.  Set the path and then stop and restart
      cmake-gui.

    - a missing mspdb80.dll.

      This file is installed with Visual Studio 2008, and is apparently
      required by cmake; you may find it on c:\vs2008\Common7\IDE ,
      where \vs2008 is a junction pointing to C:\Program Files
      (x86)\Microsoft Visual Studio 9.0 .  You may need to download and
      install VC2008 in order to get this DLL.  cmake requires it.

    - cl.exe cannot compile a simple program.

      This can happen if you don't have the LIB or INCLUDE environment
      variables set properly in the command window that you used to
      start cmake-gui. Check them, and then stop and restart cmake-gui.


9. If all goes well, the red in the cmake window will disappear.

   Now click the "Generate" button.


10. The generated makefile is placed in the build-x64 directory.

    To use the generated makefile, cd into the build-x64 directory
    and type nmake.


Notes:

When compiling PCRE for x64, there are still some glitches in the source
code.  For the v8.11 source, I had to change one file, pcregrep.c, to
correct a compile-time error.  The error was like this:

pcregrep.c
C:\dev\pcre\src\pcregrep.c(430) : warning C4013: 'pcregrep_exit' undefined; assuming extern returning int
C:\dev\pcre\src\pcregrep.c(579) : error C2371: 'pcregrep_exit' : redefinition; different basic types
C:\dev\pcre\src\pcregrep.c(1430) : warning C4267: 'function' : conversion from 'size_t' to 'int', possible loss of data


I corrected this by inserting a forward declaration for pcregrep_exit
into the pcregrep.c file.  It looks like this:

    /* forward decl */
    static void pcregrep_exit(int rc);


You need to include this anywhere in the source file before line 430.

Run nmake again, after making that change, to allow the build to
succeed.

You can also just omit the pcregrep tool from the build.  If you are
building pcre solely for the purposes of using it within IIRF, you don't
need pcregrep.  To exclude pcregrep from the build, within the cmake
window, before clicking "Generate", uncheck the box associated to
PCRE_BUILD_PCREGREP .  Then click "Generate".  Then run nmake.

After nmake succeeds, you will have a pcre.lib in the build-x64
directory.  You can copy this into the IIRF\v2.x\3rdparty\x64 directory
to allow the IIRF x64 build to succeed.
