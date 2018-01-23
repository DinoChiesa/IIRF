@echo off
goto START
=======================================================
 Uninstall.cmd

 This is part of the MSI Installer for IIRF

 Run this to uninstall the product.

 Tue, 24 Nov 2009  10:28

=======================================================

:START
@REM The uuid is the "ProductCode" in the Visual Studio setup project
@REM or the Id attribute for the top-level Product element in a Wix install. 

%windir%\system32\msiexec /x {93788b7a-62c8-4115-99dc-2fd4f8b139ba}
