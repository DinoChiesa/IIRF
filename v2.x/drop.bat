@echo OFF
goto START
=======================================================
 drop.bat

 stop IIS, copy new IIRF DLL, restart IIS

 Sat, 12 Sep 2009  08:18

=======================================================

:START
setlocal
set basepath=%~nx0

@REM defaults
set platform=x64
set config=Debug

:MORE_ARGS
set arg1=%1
if x%arg1%==x/c:Debug  (
  set config=Debug
  shift
) else if x%arg1%==x/c:Release (
  set config=Release
  shift
) else if x%arg1%==x/p:x86 (
  set platform=x86
  shift
) else if x%arg1%==x/p:x64 (
  set platform=x64
  shift
) else if x%arg1%==x? (
  goto USAGE
)

if NOT x%arg1%==x%1 goto MORE_ARGS

set arg1=%~1

:: check that an arg was passed
if xx%1 == xx (
  echo.
  echo Whoops! specify a folder to copy to.
  echo.
  goto USAGE
)


:: check existence of the folder
if not EXIST "%arg1%\." (
  echo.
  echo Whoops! that folder does not exist.
  echo.
  goto USAGE
)


:: check existence of the folder
if not xx%2 == xx (
  echo.
  echo Whoops! incorrect arguments.
  echo.
  goto USAGE
)

echo.
echo installing %platform% %config% binaries
echo.

call :ECHO_RUN net stop w3svc

set filter=bin\%platform%\%config%\IIRF.dll
set pdb=bin\%platform%\%config%\IIRF.pdb
set versiontool=bin\%platform%\%config%\IirfVersion.exe

if not EXIST %filter% then goto NOFIND

call :ECHO_RUN copy /y %filter% %1
call :MAYBECOPY %pdb% %1
call :MAYBECOPY IirfVersion.exe %1
call :ECHO_RUN net start w3svc
echo done.

goto STOPEXIT


-------------------------------------------------------
:MAYBECOPY
    if exist %1 (
      call :ECHO_RUN copy /y %1 %2
    ) else (
      if exist %2\%1  (del %2\%1)
    )
goto :EOF
-------------------------------------------------------

-------------------------------------------------------
:ECHO_RUN
    echo %*
    %*
goto :EOF
-------------------------------------------------------



-------------------------------------------------------
:NOFIND
echo.
echo Cannot find IIRF.dll. This file must be in the same directory
echo as drop.bat
echo.
goto :STOPEXIT
-------------------------------------------------------


-------------------------------------------------------
:USAGE
echo.
echo This tool will stop w3svc, copy IIRF.dll to the deployment directory,
echo and then restart w3svc.
echo.
echo Please provide a path where IIRF.dll should be dropped.
echo You can also specify whether to drop the Debug or the Release build.
echo.
echo usage:
echo.    %basepath%  ^[/c:Debug^|/c:Release^] ^[/p:x64^|/p:x86^]  ^<directory^>
echo.
goto :STOPEXIT
-------------------------------------------------------


:STOPEXIT
endlocal