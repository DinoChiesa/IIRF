@echo OFF
goto START
=======================================================

 MakeZips.cmd

 packages up zips for a release of IIRF 2.x

 Sat, 12 Sep 2009  09:03

=======================================================
:START
setlocal

set config=Release
if (x%1==x/t:Debug)  (
  set config=Debug
  shift
) else if (x%1==x/t:Release) (
  set config=Debug
  shift
)

set zipit=c:\users\dino\bin\zipit.exe
set msbuild=c:\.net4.0\msbuild.exe

for /f "tokens=1-3" %%I in ('grep FILEVERSION Filter\iirf.rc ^| grep STR ^| grep define') do set iirfVersion=%%~K

echo IIRF version: %iirfVersion%

set shortVersion=%iirfVersion:~0,3%
echo short IIRF version: %shortVersion%

if x%shortVersion%x==xx goto ERROR

if exist releases\v%iirfVersion% (
  echo That version already exists in   releases\v%iirfVersion%
  goto :STOPEXIT
)

echo making release dir releases\v%iirfVersion%
mkdir releases\v%iirfVersion%
set rdir=releases\v%iirfVersion%


echo building IIRF ISAPI dll
FOR  %%P IN  (Win32 x64) DO @call :BUILD_ISAPI %%P


:BUILDHELP
echo.
echo.
echo Building Help...
%msbuild% /nologo /p:Configuration=Release  AdminGuide\IirfGuide.shfbproj
cd %rdir%
fsutil hardlink create IirfGuide.chm  ..\..\AdminGuide\Help\IirfGuide.chm
cd ..\..

:COPY_RELNOTES
copy ReleaseNotes.txt %rdir%



:BUILD_BINZIPS
call :PACKBIN Debug x86
call :PACKBIN Release x86
call :PACKBIN Debug x64
call :PACKBIN Release x64


:BUILD_SETUP
echo.
echo.
echo Building Setup...
cd Setup
nmake /nologo clean
nmake /nologo
cd ..
copy Setup\out\IIrf%shortVersion%-x64.msi  %rdir%
copy Setup\out\IIrf%shortVersion%-x86.msi  %rdir%


:BUILD_SRCZIP
set outSrcZip=%rdir%\IonicIsapiRewriter-%iirfVersion%-src.zip
if exist %outSrcZip% (del %outSrcZip%)
%zipit%  %outSrcZip% -d 3rdParty    -D 3rdParty  -r+ -E "name != *.*~ and name != 3rdparty\_tfs\*.*"
%zipit%  %outSrcZip% -d Filter      -D Filter     -E "name != *.*~ and name != *.user AND name != *.vspscc"
%zipit%  %outSrcZip% -d TestParse   -D TestParse  -E "name != *.*~ and name != *.user AND name != *.vspscc"
%zipit%  %outSrcZip% -d Version     -D Version    -E "name != *.*~ and name != *.user AND name != *.vspscc"
%zipit%  %outSrcZip% -d TestDriver  -D TestDriver -E "name != *.*~ and name != *.user AND name != *.vspscc"

%zipit%  %outSrcZip% License.IIRF.txt Readme.txt ReleaseNotes.txt  Building.txt  IIRF.sln  makefile drop.bat .\3rdParty\License.PCRE.txt
%zipit%  %outSrcZip% -d tests -D tests -E "name != tests\*.*~"
%zipit%  %outSrcZip% -d ExampleIniFiles ExampleIniFiles
@REM %zipit%  %outSrcZip% -E "name = .\AdminGuide\Help\*.chm"

goto :STOPEXIT



--------------------------------------------
:BUILD_ISAPI
  @REM Args:  Win32 | x64
  set platform=%1
  FOR  %%C IN (Debug Release) DO (
    echo.
    echo.
    echo Building Filter %platform%  %%C
    %msbuild% /nologo /p:Configuration=%%C   /p:Platform=%platform% /t:Clean
    %msbuild% /nologo /p:Configuration=%%C   /p:Platform=%platform%
  )
goto :EOF
--------------------------------------------



-------------------------------------------------------
:PACKBIN
set config=%1
set platform=%2
set outBinZip=%rdir%\IonicIsapiRewriter-%iirfVersion%-%config%-%platform%-bin.zip
if exist %outBinZip% (del %outBinZip%)
@REM %msbuild% /nologo /property:Configuration=%config%
%zipit%  %outBinZip% -d bin -D bin\%platform%\%config%  -E "name != *.exp AND name != *.ilk"
%zipit%  %outBinZip% -s IirfVersion.txt "v%iirfVersion% %platform% %config%"  License.IIRF.txt Readme.txt ReleaseNotes.txt  .\3rdParty\License.PCRE.txt
%zipit%  %outBinZip% -d tests -D tests -E "name != tests\*.*~"
%zipit%  %outBinZip% -d ExampleIniFiles ExampleIniFiles
%zipit%  %outBinZip% -E "name = .\AdminGuide\Help\*.chm"
goto :EOF
-------------------------------------------------------


:ERROR

echo There's an error in the system, somewhere.



:STOPEXIT
endlocal
