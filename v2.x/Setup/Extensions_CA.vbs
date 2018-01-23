''
'' Extensions_CA.vbs
''
'' Custom Actions usable within WIX For IIS installations,
'' specifically for adding or removing ISAPI extensions.
''
'' The WMI model doesn't allow those things to be done from
'' Javascript, because it requires a VBArray.
''
'' ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
''
'' Last saved: <2011-April-18 01:17:41>
''
'' ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

'' spool an informational message into the MSI log, if it is enabled.
Function VBSLogMessage(msg)
    Dim record
    Set record = Session.Installer.CreateRecord(0)
    record.StringData(0) = "CustomActions: " & msg
    Session.Message &H4000000, record
End Function



Function ListScriptMaps(scriptMaps, label)
    VBSLogMessage label & " :: UBound = " & Ubound(scriptMaps)
    VBSLogMessage label & " :: LBound = " & Lbound(scriptMaps)
    VBSLogMessage "============================================"
    For i = 0 to Ubound(scriptMaps)
        VBSLogMessage scriptMaps(i).Extensions
        VBSLogMessage "  " & scriptMaps(i).ScriptProcessor
        VBSLogMessage "  " & scriptMaps(i).Flags
        VBSLogMessage "  " & scriptMaps(i).IncludedVerbs
    Next
End Function


Function CheckIisWmiProvider_VBS()
    On Error Resume Next
    VBSLogMessage("CheckIisWmiProvider_VBS() ENTER")

    Dim wmi
    wmi = Session.Property("IISWMIPROVIDER")
    If wmi = "" Then
        Err.Clear
        Dim iis
        iis = GetObject("winmgmts://localhost/root/MicrosoftIISv2")
        If Err.Number = 0 Then
            Session.Property("IISWMIPROVIDER") = "1"
        Else
            Session.Property("IISWMIPROVIDER") = "0"
        End If
        wmi = Session.Property("IISWMIPROVIDER")
    End If


    If wmi = "1" Then
        CheckIisWmiProvider_VBS = True
    Else
        CheckIisWmiProvider_VBS = False
    End If
End Function


Sub AddExtension_WMI()
    On Error Resume Next

    Dim iis
    Set iis = GetObject("winmgmts://localhost/root/MicrosoftIISv2")

    dim siteName
    siteName = Session.Property("WEBSITE_NAME")

    VBSLogMessage "website name(" & siteName & ")"

    If (siteName <> "") Then
        Dim idir, dll
        idir = Session.Property("INSTALLDIR")
        dll = idir & "IIRF.dll"

        If InStr(dll, " ") <> 0 Then
            dll = Chr(34) & dll & Chr(34)
        End If

        VBSLogMessage("Adding ISAPI Extension DLL for IIRF  path(" & dll & ")")

        Dim query
        If (siteName <> "W3SVC") Then
            query = "SELECT * FROM IIsWebServerSetting WHERE Name = '" & siteName & "'"
        Else
            query = "SELECT * FROM IIsWebServiceSetting"
        End If

        Set results = iis.ExecQuery(query)
        VBSLogMessage("results = " & TypeName(results))
        Dim newMaps()   ' dynamic Array

        For t = 0 to 1
            Dim c
            c=0
            For Each item in results
                VBSLogMessage("in the loop, t = " & t)
                If t = 0 Then
                    ListScriptMaps item.ScriptMaps, "item.ScriptMaps"
                End If
                For i = 0 to Ubound(item.ScriptMaps)
                    If UCase(item.ScriptMaps(i).Extensions) <> ".IIRF" Then
                        If t = 1 Then
                            Set newMaps(c) = item.ScriptMaps(i)
                        End if
                        c = c+1
                    End If
                Next

                If t = 0 Then
                    ReDim Preserve newMaps(c)
                Else
                    VBSLogMessage("setting new filter")

                    Set newMaps(c) = iis.get("ScriptMap").SpawnInstance_()
                    'Set additionalMap = iis.ScriptMap(".iirf", dll, 1, "Get,POST")
                    newMaps(c).Extensions = ".iirf"
                    newMaps(c).ScriptProcessor= dll
                    newMaps(c).Flags = "1"
                    newMaps(c).IncludedVerbs = ""   'nothing means "all verbs"
                    ListScriptMaps newMaps, "newMaps"
                    item.ScriptMaps = newMaps
                    item.Put_()
                End If
            Next
        Next

        VBSLogMessage("Allowing the DLL (" & dll & ") as an Extension")

        ''
        '' This is done in the <iis:WebServiceExtension> element
        '' within the Product.wxs file.  Only one or the other is required.
        '' So we comment this section out.
        ''
        ''
        ''
        '' '' The AddExtensionFile method adds a new ISAPI extension or CGI
        '' '' application to the IIS server by adding a corresponding entry
        '' '' to the WebSvcExtRestrictionList metabase property.
        '' '' =================================
        '' '' http://msdn.microsoft.com/en-us/library/ms526070.aspx
        '' Dim colItems
        '' '' ISWbemObjectSet
        '' Set colItems = iis.ExecQuery ("Select * From IIsWebService")
        ''
        '' For Each objItem in colItems
        ''     VBSLogMessage(msg)
        ''     objItem.AddExtensionFile dll, True, "Iirf", True, "Iirf Proxy Extension"
        '' Next

    End If

    Set iis = Nothing

End Sub



Function RunAppCmd_VBS (Command)
    Dim altmsg
    altmsg = Replace(command,"[","[\[]")
    altmsg = Replace(altmsg,"]","[\]]")

    VBSLogMessage("RunAppCmd_VBS(" & altmsg & ") ENTER")

    Dim wshell, fso
    Set wshell = CreateObject("WScript.Shell")
    Set fso = CreateObject("Scripting.FileSystemObject")

    Dim tmpdir, tmpFileName, windir, appcmd
    tmpdir = fso.GetSpecialFolder(2)
    tmpFileName = fso.BuildPath(tmpdir, fso.GetTempName())
    windir = fso.GetSpecialFolder(0)
    appcmd = fso.BuildPath(windir,"system32\inetsrv\appcmd.exe") & " " & Command

    altmsg = Replace(appcmd,"[","[\[]")
    altmsg = Replace(altmsg,"]","[\]]")

    VBSLogMessage("shell.Run(" & altmsg & ")")

    ' use cmd.exe to redirect the output
    Dim rc
    rc = wshell.Run("%comspec% /c " & appcmd & "> " & tmpFileName, 0, True)
    VBSLogMessage("shell.Run rc = "  & rc)

    ' emit output into MSI log file
    dim textStream
    Set textStream= fso.OpenTextFile(tmpFileName, 1)
    While Not textStream.AtEndOfStream
        Dim oneLine
        oneLine = textStream.ReadLine()
        VBSLogMessage("out: " & oneLine)
    Wend
    textStream.Close()

    fso.DeleteFile(tmpFileName)
    Set textStream = Nothing
    Set fso = Nothing
    Set wshell = Nothing

    RunAppCmd_VBS = rc

End Function


'' http://technet.microsoft.com/en-us/library/cc754147(WS.10).aspx
Sub AddExtension_Appcmd()
    Dim idir, dll

    idir = Session.Property("INSTALLDIR")
    dll = idir & "IIRF.dll"

    ' see http://www.robertdickau.com/msi_tips.html and
    ' http://msdn.microsoft.com/en-us/library/Aa368609
    ' [\[]Bracket Text[\]] resolves to [Bracket Text].

    ' But this is misleading. If you look in the MSI Log, you will see
    ' that the stuff btwn square backets resolves to *nothing*. But when
    ' passed to wshell.Run(), the same square bracket resolution
    ' does not occur, which means a string that shows up correctly
    ' in the log will be wrong for appcmd, and a string that is correct
    ' for appcmd will show up wrong in the MSI log.

    Dim cmd
    cmd = "set config /section:handlers " & Chr(34) & _
        "/+[" & _
        "name='IIRF-2.1-Proxy-ISAPI',path='*.iirf',verb='*',"& _
        "scriptProcessor='" & dll & "'" & _
        "]" & Chr(34)
    ' cmd = "set config /section:handlers " & Chr(34) & _
    '     "/+[\[]" & _
    '     "name='IIRF-2.1-Proxy-ISAPI',path='*.iirf',Verb='*',"& _
    '     "scriptProcessor='" & dll & "'" & _
    '     "[\]]" & Chr(34)

    RunAppCmd_VBS(cmd)

End Sub




Function AddExtension_CA()
    VBSLogMessage("AddExtension_CA() ENTRY")
    If CheckIisWmiProvider_VBS() Then
        AddExtension_WMI()
    Else
        AddExtension_Appcmd()
    End If

    VBSLogMessage("AddExtension_CA() EXIT")

    AddExtension_CA = 1   ' MsiActionStatus.Ok

End Function





Sub RemoveExtension_WMI()

    VBSLogMessage("RemoveExtension_WMI() ENTRY")

    Dim iis
    Set iis = GetObject("winmgmts://localhost/root/MicrosoftIISv2")

    Dim extension
    extension = ".IIRF"

    dim siteName
    siteName = Session.Property("IIRF_SITE")

    VBSLogMessage("website name(" & siteName & ")")

    If (siteName <> "") Then

        Dim query
        If (siteName <> "W3SVC") Then
            query = "SELECT * FROM IIsWebServerSetting WHERE Name = '" & siteName & "'"
        Else
            query = "SELECT * FROM IIsWebServiceSetting"
        End If

        Set results = iis.ExecQuery(query)
        Dim newMaps()   ' dynamic Array
        Dim needReset
        needReset = True
        Dim foundIirf

        '' 2 passes: the first to count, the second to do.
        For t = 0 to 1
            Dim c
            c=0
            foundIirf = False
            For Each item in results
                If t = 0 Then
                    ListScriptMaps item.ScriptMaps, "item.ScriptMaps"
                End If

                If needReset Then
                    For i = 0 to Ubound(item.ScriptMaps)
                        If UCase(item.ScriptMaps(i).Extensions) <> extension Then
                            If t = 1 Then
                                Set newMaps(c) = item.ScriptMaps(i)
                            End if
                            c = c+1
                        Else
                            foundIirf = True
                        End If
                    Next
                End If

                If Not foundIirf Then
                    needReset = False
                End If

                If needReset Then
                    If t = 0 Then
                        ReDim Preserve newMaps(c-1)
                    Else
                        VBSLogMessage("setting new scriptmaps")
                        ListScriptMaps newMaps, "newMaps"
                        item.ScriptMaps = newMaps
                        item.Put_()
                    End If
                End If
            Next
        Next

        ''
        '' This is done in the <iis:WebServiceExtension> element
        '' within the Product.wxs file.  Only one or the other is required.
        '' So we comment this section out.
        ''
        ''
        '' dim IIsWebServiceObj
        '' Set IIsWebServiceObj = GetObject("IIS://localhost/W3SVC")
        '' Dim idir, dll
        '' idir = "c:\abba\dabba\dooo"
        '' dll = idir & "IIRF.dll"
        '' IIsWebServiceObj.DeleteExtensionFileRecord(dll)
        '' Set IIsWebServiceObj = Nothing

    End If

    Set iis = Nothing

    VBSLogMessage("RemoveExtension_WMI() EXIT")

End Sub


'' http://technet.microsoft.com/en-us/library/cc754894(WS.10).aspx
Sub RemoveExtension_Appcmd()

    ' see http://msdn.microsoft.com/en-us/library/Aa368609
    ' [\[]Bracket Text[\]] resolves to [Bracket Text].
    ' But, See the note in AddExtension_Appcmd().

    Dim cmd
    cmd = "set config /section:handlers " & Chr(34) & _
        "/-[" &  "name='IIRF-2.1-Proxy-ISAPI'" & "]" & Chr(34)
    ' cmd = "set config /section:handlers " & Chr(34) & _
    '     "/-[\[]" &  "name='IIRF-2.1-Proxy-ISAPI'" & "[\]]" & Chr(34)
    RunAppCmd_VBS(cmd)
End Sub


Function RemoveExtension_CA()
    VBSLogMessage("RemoveExtension_CA() ENTRY")
    If CheckIisWmiProvider_VBS() Then
        RemoveExtension_WMI()
    Else
        RemoveExtension_Appcmd()
    End If

    VBSLogMessage("RemoveExtension_CA() EXIT")

    RemoveExtension_CA = 1   ' MsiActionStatus.Ok

End Function









