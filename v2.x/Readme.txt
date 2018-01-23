Sun, 17 Apr 2011  19:46

Readme - Ionic's Isapi Rewrite Filter (IIRF)  2.1


IIRF is an open source rewriting filter for IIS 6, and 7.x.

This readme tells you how to build IIRF from the source.

If you want to simply USE IIRF, you don't need this Readme file.  To USE
IIRF, just download a binary release from http://iirf.codplex.com, and
read the accompanying documentation (CHM file).



License
---------------------------------

Ionic's ISAPI Rewrite Filter (IIRF) is an add-on to IIS that can
rewrite URLs.  IIRF and its documentation is distributed under
the Microsoft Permissive License.  See the License.IIRF.txt file for
full details.

IIRF depends upon PCRE, which is licensed independently and
separately.  Consult the 3rdParty\License.PCRE.txt file for details.






Implementation
---------------------------------

This filter is implemented in C.
IIRF compiles with the Microsoft VC9 compiler, which ships with
Visual Studio 2008.

It may also build with Visual C++ 2008 Express Edition, but I haven't
tested it.  Express is a free version of  Visual Studio.
For more information on it, see
http://www.microsoft.com/express/vc

The compiler (cl.exe) is the same, for the Express and the commercial
Visual Studio offering. It produces the same code.

It can also be compiled with the VC++ 2010 compiler. Or, it can be
compiled with the c/C++ compiler that is available in the Windows SDK.




Pre-requisites for building
--------------------------------------------

Visual Studio 2008 -or-
Visual Studio 2010 -or-
  Visual C++ 2008 Express -or-
  Visual C++ 2010 Express -or-
  Windows SDK 7.0 or later

  http://msdn.microsoft.com/vstudio/express/visualc/
  You need only the compiler to build the source.

  If you are building for an x64 machine, you will need the Windows SDK
  or the commercial Visual Studio tool.  The Express tool does not
  include the x64 compiler, as far as I know.



Microsoft Windows SDK download (WS2008 Edition or later)
  http://www.microsoft.com/downloads/details.aspx?familyid=E6E1C3DF-A74F-4207-8586-711EBE331CDC&displaylang=en
  You need this for the header files and libraries.
  You only need the IIS portion of the SDK.






IIRF uses Third-party software
--------------------------------------------

IIRF depends on PCRE for the regular expression support.  The version of
PCRE used in IIRF is v7.8 (from 2008) or later.  The source distribution of IIRF
re-distributes the PCRE binary.  Check the PCRE license file for
information on how PCRE is licensed.

You can choose to build PCRE yourself, or just use the binary that is
packaged with IIRF.





Building the Filter
---------------------------------

If you'd like to compile IIRF, you can use the C++ compiler
that ships with Visual Studio 2005 or 2008, or you can also use the free
version of the Microsoft C++ compiler and tools, called
Microsoft Visual C++ {2005,2008} Express.  It is available here:

  http://www.microsoft.com/express/download/

If you use the VC++ Express, then you will also need to download
and install the Microsoft Windows SDK, previously known as the Windows
Platform SDK.  The SDK includes
headers and include files used by the build.  You should get the latest
SDK - the one for Windows Vista or Windows Server 2008.  The SDK is
available from here:

  http://www.microsoft.com/downloads/details.aspx?familyid=E6E1C3DF-A74F-4207-8586-711EBE331CDC&displaylang=en

The Windows SDK is large and modular - there are subsets of the Windows
SDK that cover things from the filesystem, to device drivers, to
transactions, and many others. You need at least the core files and the
IIS SDK.

You may want to download the Windows SDK een if you have the full
version of Visual Studio.  The downloadable Windows SDK includes updates
from the SDK components that are included with Visual Studio.


Summary:
To build the filter, you need these pre-requisites:

1. a build tool; Either:
 - the Microsoft Visual C++ 2005 Express, plus
   the Microsoft Windows Platform SDK (core files plus IIS SDK).
   The latter includes headers and lib files used by this project.

or:
 - Microsoft Visual Studio 2005 or 2008
   This one includes the headers and libs you need.
   and optionally,
   the Microsoft Windows Platform SDK (core files plus IIS SDK).


Either of the above also includes a make utility, nmake.exe .


2.
 - a PCRE statically linked library, pcre.lib plus the pcre.h
   header file.  These are included in the IIRF
   distribution. You can also download them directly from www.pcre.org.


You have two options for building IIRF: within the Visual Studio IDE
using the IIRF.sln solution, or from the command-line, using a makefile.

In either case, you will need to modify the settings for the project -
either in the makefile or in the Project and solution settings within
Visual Studio - IIRF to specify the locations of the Windows SDK.


After you make those changes:


A. To build with nmake:

   nmake CONFIG=Release all

      or

   nmake CONFIG=Debug all


B. To build from within Visual Studio,

   in Visual Studio, right click on the Solution in
   solution explorer, and click Rebuild.


To build the x64 version of the library:


   nmake CONFIG=Release  PLATFORM=x64 all

      or

   nmake CONFIG=Debug PLATFORM=x64  all




Building The Help File (CHM)
---------------------------------
There's a .shfbproj file for building the helpfile.  To build this you
need Sandcastle, the Sandcastle Helpfile Builder, and The Sandcastle
Styles. You also need the Microsoft HTML Help v1 compiler.  All of these
are free downloads.

Once you have downloaded and installed all these tools, cd to the
.\AdminGuide directory and invoke the buildhelp command file:


    .\buildhelp.cmd





Building The Setup (MSI)
---------------------------------

There's a project for building the installer, too.  As of v2.1.1.26 of
the source distribution of IIRF, the build for the Setup is
integrated into the toplevel Visual Studio solution and nmakefile for
IIRF.

You can also build it separately, by invoking nmake, from a command
prompt, when the current directory is the Setup directory.

To build this you will need the Wix toolkit v3.5.  See
http://wix.codeplex.com to download it. (Free)

And you will need to have successfully compiled the filter and the help
file (See above.)

Do not use WiX v3. You must use v3.5 or later.  Using Wix v3 will allow
the MSI to build successfully, but the produced setup will not run
successfully.



Building PCRE
---------------------------------

IIRF includes a pre-built binary version of the PCRE library, so
it is not required that you download or build a PCRE library to
use IIRF.  However, you may wish to download and build PCRE
yourself.  To download it, go to: http://www.pcre.org/

The procedure for building the static  PCRE library on Windows, for use
within IIRF, is documented in the Readme.txt in the 3rdParty directory
in the IIRF source package.

You use the free, open-source cmake utility to create a makefile for
PCRE.  IIRF does not include any source code for PCRE.  You can get that
separately.

As of v2.1 of IIRF (29 May 2010), IIRF uses PCRE version 8.01.  This was
the current version of PCRE at that time.




Futures
---------------------------------

I welcome feedback on IIRF.  Let me know if you've used it,
and how it went.  Let me know of bugs you find or troubles you
have.  Let me know what other features you would like to see.

Do all this on the IIRF site:
   http://iirf.codeplex.com/






Bugs
---------------------------------
 - Not well tested on clustered IIS.
 - Unicode?  what's unicode?
 - Performance has not been well measured.
 - There is no MRU cache employed for URL re-writing.
 - No rollover of text-based Log files




Fixed Bugs / Change History
---------------------------------

(See ReleaseNotes.txt)




Updates
---------------------------------

Check for the latest updates at:
  http://IIRF.codeplex.com/





-Dino Chiesa

dpchiesa@hotmail.com
