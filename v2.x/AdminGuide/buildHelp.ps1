# buildHelp.ps1
#
# Sets the IIRF version number in the .shfbproj file, then builds the help file.
#
# ------------------------------------------------------------------

param (
[string] $filename = "..\bin\x86\Release\IIRF.dll"
)

$filename = [IO.Path]::GetFullPath( $filename )

cd ..
c:\vc9\bin\nmake.exe CONFIG=Release PLATFORM=x86 filter
cd AdminGuide


$info= [system.Diagnostics.FileVersionInfo]::GetVersionInfo($filename)
write-output $info.filedescription
write-output $info.fileversion

$v = $info.fileversion
$newFooter="<FooterText>IIRF v$v</FooterText>"

$projFile = get-childitem IirfGuide.shfbproj

if ($projFile.Attributes -band [System.IO.FileAttributes]::ReadOnly)
{
    # checkout the file for edit, using the tf.exe too, and
    # passing the CodePlex authn info on cmd line
    c:\vs2010\common7\IDE\tf  edit $projFile.FullName $env:cplogin
}


Write-output "Updating version in  $projFile  to  v$v"
write-output ""

$TmpFile = $projFile.FullName + ".tmp"

get-content  $projFile.FullName |
  %{$_ -replace '<FooterText>(.+)</FooterText>', $newFooter } |
  Out-File -Encoding ASCII $TmpFile

move-item $TmpFile $projFile.FullName -force

c:\.net3.5\msbuild.exe  /p:Configuration=Release   IirfGuide.shfbproj
