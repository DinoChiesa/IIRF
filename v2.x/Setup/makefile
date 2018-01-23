#
# NMakefile for WIX installer, for IIRF
#
# Wed, 25 Nov 2009  11:58
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


## Notes:
## --------
## 1. The ..\License.rtf file is referenced implicitly in the Product.wxs file.
##
## 2. There's a different MSI for x86 and x64.
##


#WIXDIR=c:\Program Files\Windows Installer XML v3
WIXDIR=c:\wix


CANDLE=$(WIXDIR)\bin\candle.exe
LIGHT=$(WIXDIR)\bin\light.exe
CSCRIPT=$(WINDIR)\System32\cscript.exe


default: all

all: out\Iirf2.1-x86.msi out\Iirf2.1-x64.msi

x86: out\Iirf2.1-x86.msi

x64: out\Iirf2.1-x64.msi


        # "$(CANDLE)" -ext WixIIsExtension   -ext WixUtilExtension  Product.wxs UI.wxs SelectWebSiteDlg.wxs  CustomActions.wxs -o out\\

out\Iirf2.1-x86.msi:  Product.wxs UI.wxs SelectWebSiteDlg.wxs CustomActions.wxs  CustomText.wxl makefile  ..\bin\x86\Release\Iirf.dll ..\readme.txt   ..\AdminGuide\Help\IirfGuide.chm  CustomActions.js PostProcessMsi.js Extensions_CA.vbs ..\License.rtf
        if not EXIST out\x86 (mkdir out\x86)
        -echo y | del /s out\x86\*.*
        "$(CANDLE)" -dPlatform=x86 -ext WixIIsExtension   -ext WixUtilExtension  Product.wxs UI.wxs SelectWebSiteDlg.wxs  CustomActions.wxs -o out\x86\\
        "$(LIGHT)" -sw1076 -ext WixUIExtension -ext WixIIsExtension -ext WixUtilExtension  -o out\Iirf2.1-x86.msi -loc CustomText.wxl out\x86\Product.wixobj out\x86\UI.wixobj out\x86\SelectWebSiteDlg.wixobj out\x86\CustomActions.wixobj
        "$(CSCRIPT)" PostProcessMsi.js out\Iirf2.1-x86.msi


out\Iirf2.1-x64.msi:  Product.wxs UI.wxs SelectWebSiteDlg.wxs CustomActions.wxs  CustomText.wxl makefile  ..\bin\x64\Release\Iirf.dll ..\readme.txt   ..\AdminGuide\Help\IirfGuide.chm  CustomActions.js PostProcessMsi.js Extensions_CA.vbs ..\License.rtf
        if not EXIST out\x64 (mkdir out\x64)
        -echo y | del /s out\x64\*.*
        "$(CANDLE)" -dPlatform=x64 -ext WixIIsExtension   -ext WixUtilExtension  Product.wxs UI.wxs SelectWebSiteDlg.wxs  CustomActions.wxs -o out\x64\\
        "$(LIGHT)"  -sw1076 -ext WixUIExtension -ext WixIIsExtension -ext WixUtilExtension  -o out\Iirf2.1-x64.msi -loc CustomText.wxl out\x64\Product.wixobj out\x64\UI.wixobj out\x64\SelectWebSiteDlg.wixobj out\x64\CustomActions.wixobj
        "$(CSCRIPT)" PostProcessMsi.js out\Iirf2.1-x64.msi



clean:
        -echo y | rd /s out


