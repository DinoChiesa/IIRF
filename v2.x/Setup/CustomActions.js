//
// CustomActions.js
//
// Custom Actions usable within WIX For IIS installations.
//
// EnumerateWebSites_CA():
//   Adds new UI to the MSI at runtime to allow the user to select a
//   website, to which an ISAPI filter will be added.
//
// UpdatePropsWithSelectedWebSite_CA():
//   Fills session with properties for the selected website.
//   Also sets the InstallText of the VerifyReadyDlg.
//
// SetAuthProps_CA():
//   sets properties for the needed user and group that needs
//   authorization to the created dir.
//
// ShutdownIisSites_CA():
//   stops sites that are running. Done only on uninstall, to allow the IIRF.dll
//   to be removed.
//
// StartIisSites_CA():
//   restart IIS Sites.  Done only on uninstall, after IIRF.dll has been deleted.
//
// SetWebsitePropsForUninstall_CA():
//   sets WEBSITE_DESCRIPTION, etc.  Called only during uninstall.
//
//
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Created:
// Mon, 23 Nov 2009  10:54
//
// Last saved: <2011-April-25 18:10:51>
//
// ===================================================================



// http://msdn.microsoft.com/en-us/library/aa372516(VS.85).aspx
var MsiViewModify = {
        Refresh          : 0,
        Insert           : 1,
        Update           : 2,
        Assign           : 3,
        Replace          : 4,
        Merge            : 5,
        Delete           : 6,
        InsertTemporary  : 7,   // cannot permanently modify the MSI during install
        Validate         : 8,
        ValidateNew      : 9,
        ValidateField    : 10,
        ValidateDelete   : 11
    };


// http://msdn.microsoft.com/en-us/library/aa371662(VS.85).aspx
var MsiInstallState = {
        Unknown          : -1, // no action is being taken
        Advertised       : 1,
        Absent           : 2,
        RunLocal         : 3,
        RunFromSource    : 4,
        ReinstallDefault : 5   // to be re-installed with the feature's current state
    };


// // from msidefs.h, or see http://msdn.microsoft.com/en-us/library/aa368077(VS.85).aspx
// var MsidbCustomActionType = {
//         // executable types
//         Dll              : 0x00000001, // Target = entry point name
//         Exe              : 0x00000002, // Target = command line args
//         TextData         : 0x00000003, // Target = text string to be formatted and set into property
//         JScript          : 0x00000005, // Target = entry point name, null if none to call
//         VBScript         : 0x00000006, // Target = entry point name, null if none to call
//         Install          : 0x00000007, // Target = property list for nested engine initialization
//
//         // source of code
//         BinaryData       : 0x00000000, // Source = Binary.Name, data stored in stream
//         SourceFile       : 0x00000010, // Source = File.File, file part of installation
//         Directory        : 0x00000020, // Source = Directory.Directory, folder containing existing file
//         Property         : 0x00000030, // Source = Property.Property, full path to executable
//
//         // return processing.  default is synchronous execution, process return code
//         Continue         : 0x00000040, // ignore action return status, continue running
//         Async            : 0x00000080  // run asynchronously
//     };


// http://msdn.microsoft.com/en-us/library/sfw6660x(VS.85).aspx
var Buttons = {
    OkOnly           : 0,
    OkCancel         : 1,
    AbortRetryIgnore : 2,
    YesNoCancel      : 3
};

var Icons= {
    Critical         : 16,
    Question         : 32,
    Exclamation      : 48,
    Information      : 64
};

var MsgKind = {
    Error            : 0x01000000,
    Warning          : 0x02000000,
    User             : 0x03000000,
    Log              : 0x04000000
};

// http://msdn.microsoft.com/en-us/library/aa371254(VS.85).aspx
var MsiActionStatus = {
    None             : 0,
    Ok               : 1, // success
    Cancel           : 2,
    Abort            : 3,
    Retry            : 4, // aka suspend?
    Ignore           : 5  // skip remaining actions; this is not an error.
};


// http://msdn.microsoft.com/en-us/library/ms524905.aspx
var IisServerState = {
    Starting   : 1,
    Started    : 2,
    Stopping   : 3,
    Stopped    : 4,
    Pausing    : 5,
    Paused     : 6,
    Continuing : 7,
    toString   : function(value) {
        switch(value) {
        case 1:
            return "Starting";
        case 2:
            return "Started";
        case 3:
            return "Stopping";
        case 4:
            return "Stopped";
        case 5:
            return "Pausing";
        case 6:
            return "Paused";
        case 7:
            return "Continuing";
        default:
            return "Unknown";
        }
    }
};

var Exception = function(type, description, optionalNumber) {
    var instance         = {};
    instance.type        = type || "Exception";
    instance.description = description || "unknown exception";
    instance.number      = optionalNumber || 0;
    return instance;
};


// Format a number as hex.  Quantities over 7ffffff will be displayed properly.
function decimalToHexString(number) {
    if (number < 0) {
        number = 0xFFFFFFFF + number + 1;
    }
    return number.toString(16).toUpperCase();
}



// Pop a message box.  also spool a message into the MSI log, if it is enabled.
function LogException(loc, exc) {
    var record = Session.Installer.CreateRecord(0);
    record.StringData(0) = "Exception {" + loc + "}: 0x" + decimalToHexString(exc.number) + " : " + exc.message;
    Session.Message(MsgKind.Error + Icons.Critical + Buttons.btnOkOnly, record);
}



// spool an informational message into the MSI log, if it is enabled.
function LogMessage(msg) {
    var record = Session.Installer.CreateRecord(0);
    record.StringData(0) = "CustomActions: " + msg;
    Session.Message(MsgKind.Log, record);
}


// popup a msgbox
function AlertUser(msg) {
    var record = Session.Installer.CreateRecord(0);
    record.StringData(0) = msg;
    Session.Message(MsgKind.User + Icons.Information + Buttons.btnOkOnly, record);
}



// http://msdn.microsoft.com/en-us/library/d5fk67ky(VS.85).aspx
var WindowStyle = {
    Hidden    : 0,
    Minimized : 1,
    Maximized : 2
};

// http://msdn.microsoft.com/en-us/library/314cz14s(v=VS.85).aspx
var OpenMode = {
    ForReading   : 1,
    ForWriting   : 2,
    ForAppending : 8
};

// http://msdn.microsoft.com/en-us/library/a72y2t1c(v=VS.85).aspx
var SpecialFolders = {
    WindowsFolder   : 0,
    SystemFolder    : 1,
    TemporaryFolder : 2
};



function RunAppCmd(command, deleteOutput) {
    deleteOutput = deleteOutput || false;
    LogMessage("RunAppCmd("+command+") ENTER");
    var shell = new ActiveXObject("WScript.Shell");
    var fso = new ActiveXObject("Scripting.FileSystemObject");
    var tmpdir = fso.GetSpecialFolder(SpecialFolders.TemporaryFolder);
    var tmpFileName = fso.BuildPath(tmpdir, fso.GetTempName());
    var windir = fso.GetSpecialFolder(SpecialFolders.WindowsFolder);
    var appcmd = fso.BuildPath(windir,"system32\\inetsrv\\appcmd.exe") + " " + command;

    LogMessage("shell.Run("+appcmd+")");

    // use cmd.exe to redirect the output
    var rc = shell.Run("%comspec% /c " + appcmd + "> " + tmpFileName, WindowStyle.Hidden, true);
    LogMessage("shell.Run rc = "  + rc);

    if (deleteOutput) {
        fso.DeleteFile(tmpFileName);
    }
    return {
        rc : rc,
        outputfile : (deleteOutput) ? null : tmpFileName
    };
}



// GetWebSites_Appcmd()
//
// Gets website info using Appcmd.exe, only on IIS7+ .
//
// This fn always returns site state info with each record.
//
function GetWebSites_Appcmd() {
    var ParseOneLine = function(oneLine) {
        // split the string: capture quoted strings, or a string surrounded
        // by parens, or lastly, tokens separated by spaces,
        var tokens = oneLine.match(/"[^"]+"|\(.+\)|[^ ]+/g);

        // split the 3rd string: it is a set of properties separated by colons
        var props = tokens[2].slice(1,-1);
        var t2 = props.match(/\w+:.+?(?=,\w+:|$)/g);
        var bindingsString = t2[1];
        //say(bindingsString);
        var ix1 = bindingsString.indexOf(':');
        var t3 = bindingsString.substring(ix1+1).split(',');

        var bindings = {};
        for (var i=0; i<t3.length; i++) {
            var split = t3[i].split('/');
            var obj = {};
            if (split[0] == "net.tcp") {
                var p2 = split[1].split(':');
                obj.port = p2[0];
            }
            else if (split[0] == "net.pipe") {
                var p3 = split[1].split(':');
                obj.other = p3[0];
            }
            else if (split[0] == "http") {
                var p4 = split[1].split(':');
                obj.ip = p4[0];
                if (p4[1]) {
                    obj.port = p4[1];
                }
                obj.hostname = "";
            }
            else {
                var p5 = split[1].split(':');
                obj.hostname = p5[0];
                if (p5[1]) {
                    obj.port = p5[1];
                }
            }
            bindings[split[0]] = obj;
        }

        // return the object describing the website
        return {
            id          : t2[0].split(':')[1],
            name        : "W3SVC/" + t2[0].split(':')[1],
            description : tokens[1].slice(1,-1),
            bindings    : bindings,
            state       : t2[2].split(':')[1] // started or not
        };
    };

    LogMessage("GetWebSites_Appcmd() ENTER");

    var r = RunAppCmd("list sites");
    if (r.rc !== 0) {
        // 0x80004005 == E_FAIL
        throw new Exception("ApplicationException", "exec appcmd.exe returned nonzero rc ("+r.rc+")", 0x80004005);
    }

    var fso = new ActiveXObject("Scripting.FileSystemObject");
    var textStream = fso.OpenTextFile(r.outputfile, OpenMode.ForReading);
    var sites = [];

    // Read from the file and parse the results.
    while (!textStream.AtEndOfStream) {
        var oneLine = textStream.ReadLine();
        var line = ParseOneLine(oneLine);
        LogMessage("  site: " + line.name);
        sites.push(line);
    }
    textStream.Close();
    fso.DeleteFile(r.outputfile);

    LogMessage("GetWebSites_Appcmd() EXIT");

    return sites;
}




function GetWebSites_WMI(wantState) {
    LogMessage("GetWebSites_WMI("+wantState+") ENTER");

    var iis = GetObject("winmgmts://localhost/root/MicrosoftIISv2");
    var query  = (wantState) ? "SELECT * FROM IIsWebServer" :
        "SELECT * FROM IIsWebServerSetting";
    // get the list of virtual servers (aka sites)
    var results = iis.ExecQuery(query);
    var sites = [];

    for(var e = new Enumerator(results); !e.atEnd(); e.moveNext()) {
        var item = e.item();

        if (wantState) {
            // see http://msdn.microsoft.com/en-us/library/ms525545.aspx
            sites.push({ name  : item.Name,
                         state : IisServerState.toString(item.ServerState) });
        }
        else {
            // WMI obj property             Examples
            // =======================================================
            // item.Name                    W3SVC/1, W3SVC/12378398, etc
            // item.Name.substr(6)          1, 12378398, etc
            // item.ServerComment           "Default Web Site", "Site2", etc
            // item.ServerBindings(0).Port  80, 8080, etc

            var rawBindings = item.ServerBindings.toArray();

            // transform the array of bindings into an associative array
            var a = {};
            a.http = {
                port     : rawBindings[0].Port,
                ip       : rawBindings[0].Ip,
                hostname : rawBindings[0].Hostname };

            sites.push({ name        : item.Name,
                         id          : item.Name.substr(6),
                         description : item.Servercomment,
                         bindings    : a });
        }
    }
    LogMessage("GetWebSites_WMI() EXIT");
    return sites;
}




// CheckIisWmiProvider()
//
// return true if WMI provider is present.
//
function CheckIisWmiProvider() {
    LogMessage("CheckIisWmiProvider() ENTER");
    var wmi = Session.Property("IISWMIPROVIDER");
    if (wmi === null || wmi== "") {
        try {
            var iis = GetObject("winmgmts://localhost/root/MicrosoftIISv2");
            Session.Property("IISWMIPROVIDER") = "1";
        }
        catch (exc1) {
            Session.Property("IISWMIPROVIDER") = "0";
        }
        wmi = Session.Property("IISWMIPROVIDER");
    }

    LogMessage("CheckIisWmiProvider() EXIT (wmi="+ wmi+")");
    return (wmi == "1");
}



function GetWebSites(wantState) {
    wantState = wantState || false; // default
    LogMessage("GetWebSites("+wantState+") ENTER");

    var wmi = CheckIisWmiProvider();
    var iis6 = Session.Property("IIS56");
    if (iis6 != "#0") {
        if (!wmi) {
            throw new Exception("ApplicationException", "IIS6, but WMI provider was not found", 0x80004001);
        }
        return GetWebSites_WMI(wantState);
    }

    var iisversion = Session.Property("IISMAJORVERSION");
    if (iisversion == "#6") {
        if (wmi) {
            return GetWebSites_WMI(wantState);
        }
        throw new Exception("ApplicationException", "WMI for IIS is required on IIS6", 0x80004001);
    }
    else if (iisversion == "#7") {
        return GetWebSites_Appcmd();
    }

    throw new Exception("ApplicationException", "IIS 6 or 7 is not installed", 0x80004001);
}






function EnumerateWebSites_CA() {
    try {
        LogMessage("EnumerateWebSites_CA() ENTER");

        var c = 1;
        var serverBindings, aBindings;

        var listboxesView = Session.Database.OpenView("SELECT * FROM ListBox");
        listboxesView.Execute();

        var record = Session.Installer.CreateRecord(4);
        record.StringData(1) = "WEBSITE";     // Property
        record.IntegerData(2) = c++;          // display order
        record.StringData(3) = "Server";      // returned by the selection
        record.StringData(4) = "Server-wide"; // displayed in the UI
        listboxesView.Modify(MsiViewModify.InsertTemporary, record);

        // Create this table dynamically.  We could also create this
        // custom table in the WiX .wxs file , but that's not necessary.

        var query = "CREATE TABLE AvailableWebSites " +
            "(Num INT NOT NULL, Name CHAR(64), Desc CHAR(64), Port CHAR(16) NOT NULL, IP CHAR(32), Hostname CHAR(80) PRIMARY KEY Num)";
        var createCmd = Session.Database.OpenView(query);
        createCmd.Execute();
        createCmd.Close();

        LogMessage("Table 'AvailableWebSites' has been created");

        var websitesView = Session.Database.OpenView("SELECT * FROM AvailableWebSites");
        websitesView.Execute();

        var sites = GetWebSites();

        LogMessage("Websites Query completed.  results: " + typeof sites);

        for (var i = 0; i < sites.length; i++) {
            var site = sites[i];
            // obj property                Examples
            // =======================================================
            // site.name                   W3SVC/1, W3SVC/12378398, etc
            // site.id                     1, 12378398, etc
            // site.description            "Default Web Site", "Site2", etc
            // site.bindings["http"].port  80, 8080, etc

            LogMessage("Web site " + site.name);

            LogMessage("listbox record");
            record                = Session.Installer.CreateRecord(4);
            record.StringData(1)  = "WEBSITE";
            record.IntegerData(2) = c;
            record.StringData(3)  = site.name;                       // Name, like W3SVC/1, etc
            record.StringData(4)  = site.description + " (" + site.name + ")";
            listboxesView.Modify(MsiViewModify.InsertTemporary, record);

            var httpBinding = site.bindings["http"];

            LogMessage("websites record:  num(" +
                       site.id + ") site(" + site.name + ") desc(" + site.description + ") port(" +
                       httpBinding.port + ")");

            record                = Session.Installer.CreateRecord(6);
            record.IntegerData(1) = c;                    // a primary key
            record.StringData(2)  = site.name;            // eg, W3SVC/1, etc
            record.StringData(3)  = site.description;     // eg, "My web site", etc
            record.StringData(4)  = httpBinding.port;     //
            record.StringData(5)  = httpBinding.ip;       // maybe empty
            record.StringData(6)  = httpBinding.hostname; // maybe empty
            websitesView.Modify(MsiViewModify.InsertTemporary, record);
            c++;
        }

        listboxesView.Close();
        websitesView.Close();

        LogMessage("EnumerateWebSites_CA() EXIT");
    }

    catch (exc1) {
        Session.Property("CA_EXCEPTION") = exc1.message ;
        LogException("EnumerateWebSites", exc1);
        return MsiActionStatus.Abort;
    }
    return MsiActionStatus.Ok;
}




//*****************************************************************************
// Custom action that copies the selected website's properties from the
// AvailableWebSites table to properties.
//
// Effects: Fills the WEBSITE_DESCRIPTION, WEBSITE_PORT, WEBSITE_IP, WEBSITE_HEADER
//          properties.
//
// Returns: MsiActionStatus.Ok  if the custom action executes without error.
//          MsiActionStatus.Abort if error.
//*****************************************************************************
function UpdatePropsWithSelectedWebSite_CA() {
    try {
        LogMessage("UpdatePropsWithSelectedWebSite_CA() ENTER");

        var dllInstallRequested   = Session.FeatureRequestState("F.Binary");
        var selectedWebSiteId = Session.Property("WEBSITE");

        LogMessage("selectedWebSiteId(" + selectedWebSiteId + ") type(" + typeof selectedWebSiteId + ")");

        // check if the user selected anything.
        if (dllInstallRequested != MsiInstallState.RunLocal || selectedWebSiteId == "") {
            // either the DLL feature will not be installed, or for some reason there's
            // no server selected.
            UpdateReadyDialog(selectedWebSiteId);
            LogMessage("UpdatePropsWithSelectedWebSite_CA() EXIT (None)");
            return MsiActionStatus.Ok;
        }

        if (selectedWebSiteId.toUpperCase() == "SERVER") {
            Session.Property("WEBSITE_NAME")        = "W3SVC";  // name in the metabase
            Session.Property("WEBSITE_DESCRIPTION") = "Server";
            Session.Property("WEBSITE_PORT")        = "180";  // this not is used, but it's required to be non-empty
            Session.Property("WEBSITE_IP")          = "";
            Session.Property("WEBSITE_HEADER")      = "";
            UpdateReadyDialog(selectedWebSiteId);
            LogMessage("UpdatePropsWithSelectedWebSite_CA() EXIT (Ok)");
            return MsiActionStatus.Ok;
        }

        // sanity check
        if (selectedWebSiteId.substr(0,6).toUpperCase() != "W3SVC/") {
            throw new Exception("ApplicationException", "unexpected website ID", 0x80004005);
        }

        var websitesView = Session.Database.OpenView("SELECT * FROM `AvailableWebSites` WHERE `Name`='" + selectedWebSiteId + "'");
        websitesView.Execute();
        var record = websitesView.Fetch();

        LogMessage("website Fetch() complete");

        if (record == null)
            throw new Exception("ApplicationException", "website ID not found", 0x80004005);

        Session.Property("WEBSITE_NAME")        = record.StringData(2);
        Session.Property("WEBSITE_DESCRIPTION") = record.StringData(3);
        Session.Property("WEBSITE_PORT")        = record.StringData(4);
        Session.Property("WEBSITE_IP")          = record.StringData(5);
        Session.Property("WEBSITE_HOSTNAME")    = record.StringData(6);

        websitesView.Close();

        UpdateReadyDialog(selectedWebSiteId);

        LogMessage("UpdatePropsWithSelectedWebSite_CA() EXIT (Ok)");
    }

    catch (exc1) {
        Session.Property("CA_EXCEPTION") = exc1.message ;
        LogException("UpdatePropsWithSelectedWebSite", exc1);
        return MsiActionStatus.Abort;
    }
    return MsiActionStatus.Ok;
}

//
// Delete any temp rows from the Control table. These will be present if
// the user has gone to the "ready to install?" dialog, then backs up,
// then goes forward again.
//
function ClearCustomControlRows(ctrlName) {
    var query = "DELETE  from  Control where `Control`.`Control`='" + ctrlName + "'";
    var deleteCmd = Session.Database.OpenView(query);
    deleteCmd.Execute();
    deleteCmd.Close();

    query = "DELETE  from  ControlCondition where `ControlCondition`.`Control_`='" + ctrlName + "'";
    deleteCmd = Session.Database.OpenView(query);
    deleteCmd.Execute();
    deleteCmd.Close();
}




//
// Update the text for VerifyReadyDlg to indicate the choices
// that have been made.
//
function UpdateReadyDialog(sitename) {
    LogMessage("UpdateReadyDialog ENTER");

    var dllInstallRequested   = Session.FeatureRequestState("F.Binary");
    var toolsInstallRequested = Session.FeatureRequestState("F.Tools");
    var chmInstallRequested   = Session.FeatureRequestState("F.Helpfile");
    var vText1 = "";

    if (dllInstallRequested == MsiInstallState.RunLocal) {
        if (sitename == "Server") {
            vText1 = "The IIRF binaries will be installed, and configured Server-wide.";
        }
        else {
            var name = Session.Property("WEBSITE_NAME");
            var desc = Session.Property("WEBSITE_DESCRIPTION");

            vText1 = "IIRF will be installed, and configured for the Website named '" + name + "' " +
                "with the description '" + desc + "'";
        }
    }
    else {
        vText1 = "The IIRF binaries will not be installed, and IIS will not be configured.";
    }

    vText1 += "\r\n\r\n";
    if (toolsInstallRequested == MsiInstallState.RunLocal) {
        vText1 += "The IIRF tools will be installed.";
    }
    else if (toolsInstallRequested == MsiInstallState.RunFromSource) {
        vText1 += "The IIRF tools will be available from the source MSI.";
    }
    else {
        vText1 += "The IIRF tools will not be installed.";
    }


    vText1 += "\r\n\r\n";
    if (chmInstallRequested == MsiInstallState.RunLocal) {
        vText1 += "The IIRF Help file will be installed.";
    }
    else if (chmInstallRequested == MsiInstallState.RunFromSource) {
        vText1 += "The IIRF Help file will be available from the source MSI.";
    }
    else {
        vText1 += "The IIRF Help file will not be installed.";
    }


    LogMessage("UpdateReadyDialog vText1(" + vText1 + ")");

    var text2= "Click Install to begin the installation.\r\n" +
        "Click Back to review or change any of your installation settings.\r\n" +
        "Click Cancel to exit the wizard.";

    ClearCustomControlRows("CustomVerifyText1");
    ClearCustomControlRows("CustomVerifyText2");

    var controlView     = Session.Database.OpenView("SELECT * FROM Control");
    controlView.Execute();

    var rec             = Session.Installer.CreateRecord(12);
    rec.StringData(1)   = "VerifyReadyDlg";    // Dialog_
    rec.StringData(2)   = "CustomVerifyText1"; // Control
    rec.StringData(3)   = "Text";              // Type
    rec.IntegerData(4)  = 25;                  // X
    rec.IntegerData(5)  = 60;                  // Y
    rec.IntegerData(6)  = 320;                 // Width
    rec.IntegerData(7)  = 85;                  // Height
    rec.IntegerData(8)  = 2;                   // Attributes
    rec.StringData(9)   = "";                  // Property
    rec.StringData(10)  = vText1;              // Text
    rec.StringData(11)  = "";                  // Control_Next
    rec.StringData(12)  = "";                  // Help
    controlView.Modify(MsiViewModify.InsertTemporary, rec);

    rec                 = Session.Installer.CreateRecord(12);
    rec.StringData(1)   = "VerifyReadyDlg";    // Dialog_
    rec.StringData(2)   = "CustomVerifyText2"; // Control
    rec.StringData(3)   = "Text";              // Type
    rec.IntegerData(4)  = 25;                  // X
    rec.IntegerData(5)  = 160;                 // Y
    rec.IntegerData(6)  = 320;                 // Width
    rec.IntegerData(7)  = 65;                  // Height
    rec.IntegerData(8)  = 2;                   // Attributes
    rec.StringData(9)   = "";                  // Property
    rec.StringData(10)  = text2;               // Text
    rec.StringData(11)  = "";                  // Control_Next
    rec.StringData(12)  = "";                  // Help
    controlView.Modify(MsiViewModify.InsertTemporary, rec);

    controlView.Close();

    LogMessage("UpdateReadyDialog done adding new controls...");

    var controlCondView = Session.Database.OpenView("SELECT * FROM ControlCondition");
    controlCondView.Execute();

    rec                 = Session.Installer.CreateRecord(4);
    rec.StringData(1)   = "VerifyReadyDlg";    // Dialog_
    rec.StringData(2)   = "CustomVerifyText1"; // Control_
    rec.StringData(3)   = "Show";              // Action
    rec.StringData(4)   = "NOT Installed";     // Condition
    controlCondView.Modify(MsiViewModify.InsertTemporary, rec);

    rec                 = Session.Installer.CreateRecord(4);
    rec.StringData(1)   = "VerifyReadyDlg";    // Dialog_
    rec.StringData(2)   = "CustomVerifyText2"; // Control_
    rec.StringData(3)   = "Show";              // Action
    rec.StringData(4)   = "NOT Installed";     // Condition
    controlCondView.Modify(MsiViewModify.InsertTemporary, rec);

    controlCondView.Close();

    LogMessage("UpdateReadyDialog done adding conditions...");

    LogMessage("UpdateReadyDialog EXIT");
}




//
// Conditionally applying permissions in the WiX syntax is too hard to
// understand.  I use this method to set some Installer properties,
// indicating the user & group (and domains) necessary to set perms on
// the installed DLL.
//
// Much easier this way.
//
// This Custom Action ius set to run after CostInitialize.  It will
// succeed only if IIS6 or IIS7 is present, so it must run after
// verifying that.  Which is fine, because those things are verified
// with LaunchConditions.
//
function SetAuthProps_CA() {
    try {
        LogMessage("SetAuthProps_CA() ENTER");
        var iisversion = Session.Property("IISMAJORVERSION");
        if (iisversion == "#6") {
            Session.Property("WEB_USER")         = "NetworkService";
            Session.Property("WEB_USER_DOMAIN")  = "";
            Session.Property("WEB_GROUP")        = "IIS_WPG";
            Session.Property("WEB_GROUP_DOMAIN") = "";
        }
        else if (iisversion == "#7") {
            Session.Property("WEB_USER")         = "IUSR";
            Session.Property("WEB_USER_DOMAIN")  = "NT AUTHORITY";
            Session.Property("WEB_GROUP")        = "IIS_IUSRS";
            Session.Property("WEB_GROUP_DOMAIN") = "";
        }
        else {
            // sanity check
            LogMessage("SetAuthProps_CA() Unknown IIS Version");
            LogMessage("SetAuthProps_CA() EXIT (Abort)");
            return MsiActionStatus.Abort;
        }

        LogMessage("SetAuthProps_CA() EXIT (Ok)");
    }
    catch (exc1) {
        Session.Property("CA_EXCEPTION") = exc1.message ;
        LogException("SetAuthProps", exc1);
        return MsiActionStatus.Abort;
    }
    return MsiActionStatus.Ok;
}


function StopOneIisSite_WMI(siteName)
{
    var iis = GetObject("winmgmts://localhost/root/MicrosoftIISv2");
    var query  = "SELECT * FROM IIsWebServer WHERE Name = '"+siteName+"'";
    var results = iis.ExecQuery(query);
    for(var e = new Enumerator(results); !e.atEnd(); e.moveNext()) {
        var item = e.item();
        item.Stop();
    }
}


function StopOneIisSite_Appcmd(siteDescription)
{
    LogMessage("StopOneIisSite_Appcmd() ENTER");
    var r = RunAppCmd("stop site \"" + siteDescription + "\"", true);
    if (r.rc != 0) {
        // 0x80004005 == E_FAIL
        throw new Exception("ApplicationException", "exec appcmd.exe returned nonzero rc ("+r.rc+")", 0x80004005);
    }
}




function StopOneIisSite(siteName, siteDescrip)
{
    LogMessage("StopOneIisSite("+siteName+","+siteDescrip+") ENTER");
    var wmi = CheckIisWmiProvider();
    if (wmi) {
        StopOneIisSite_WMI(siteName);
    }
    else {
        StopOneIisSite_Appcmd(siteDescrip);
    }
    LogMessage("StopOneIisSite() EXIT");
}


//
// Shutdown Websites in IIS.  This is done in case of IIRF uninstall or
// upgrade, after CostFinalize, because the IIRF DLL cannot be removed
// or copied over if a website is in use.  This CA does not get executed
// if IIRF is being *installed* on a clean machine.
//
function ShutdownIisSites_CA() {
    try {
        LogMessage("ShutdownIisSites_CA() ENTER");
        var sitesThatWereStopped = [];
        var sites = GetWebSites(true);
        for (var i = 0; i < sites.length; i++) {
            var site = sites[i];
            LogMessage("ShutdownIisSites_CA(): site(" + site.name +
                       "): " + site.state);
            if (site.state == "Started") {
                LogMessage("ShutdownIisSites_CA(): stop '" + site.name + "'");
                StopOneIisSite(site.name, site.description);
                sitesThatWereStopped.push(site.name);
            }
        }
        // remember for later
        Session.Property("CA_STOPPEDSITES") = sitesThatWereStopped.join(",");
        LogMessage("ShutdownIisSites_CA() EXIT (Ok)");
    }
    catch (exc1) {
        Session.Property("CA_EXCEPTION") = exc1.message;
        LogException("ShutdownIisSites", exc1);
        return MsiActionStatus.Abort;
    }
    return MsiActionStatus.Ok;
}


//
// Find the searchElement in the array.
// Like the indexOf function available on Arrays in Javascript 1.6.
//
function IndexOf(a,searchElement) {
    if (a === null) {
        throw new Exception("ApplicationException", "null value was not expected", 0x80004001);
    }
    var len = a.length;
    if (len === 0) { return -1; }
    var k;
    for (k=0; k < len; k++) {
        if (a[k] === searchElement) {
            return k;
        }
    }
    return -1;
}


//
// Start Websites in IIS.  This is done after StartServices, in case of
// uninstall or upgrade.  Only the sites that previously were running,
// are restarted.
//
function StartIisSites_CA() {
    try {
        LogMessage("StartIisSites_CA() ENTER");

        var stoppedSites = Session.Property("CA_STOPPEDSITES");
        if (stoppedSites != null && stoppedSites != "") {
            var sitesToStart = stoppedSites.split(",");
            LogMessage("StartIisSites_CA(): sitesToStart:");
            var wmi = CheckIisWmiProvider();
            if (wmi) {
                LogMessage("StartIisSites_CA(): using WMI");
                for (var k=0; k<sitesToStart.length; k++) {
                    LogMessage("StartIisSites_CA(): '" + sitesToStart[k] + "'");
                }
                var iis = GetObject("winmgmts://localhost/root/MicrosoftIISv2");
                var query = "SELECT * FROM IIsWebServer";
                var results = iis.ExecQuery(query);
                for (var e = new Enumerator(results); !e.atEnd(); e.moveNext()) {
                    var site = e.item();
                    if (IndexOf(sitesToStart,site.Name) != -1) {
                        LogMessage("StartIisSites_CA(): site '" + site.Name + "' start");
                        site.Start();
                    }
                    //else {
                    //    LogMessage("StartIisSites_CA(): site '" + site.Name + "' no action");
                    //}
                }
            }
            else {
                // using IIS7
                LogMessage("StartIisSites_CA(): using Appcmd");
                var sites = GetWebSites();
                for (var k2=0; k2<sitesToStart.length; k2++) {
                    // sitesToStart contains the site name, eg "W3SVC/1".
                    // appcmd requires the site description, eg "Default Web Site"
                    LogMessage("StartIisSites_CA(): '" + sitesToStart[k2] + "'");
                    var descrip = "";
                    for (var k3=0; k3<sites.length; k3++) {
                        if (sites[k3].name == sitesToStart[k2]) {
                            descrip = sites[k3].description;
                        }
                    }
                    if (descrip != "") {
                        // found
                        var r = RunAppCmd("start site \"" + descrip + "\"", true);
                    }
                }
            }
        }
        LogMessage("StartIisSites_CA() EXIT (Ok)");
    }
    catch (exc1) {
        Session.Property("CA_EXCEPTION") = exc1.message ;
        LogException("StartIisSites", exc1);
        return MsiActionStatus.Abort;
    }
    return MsiActionStatus.Ok;
}



//*****************************************************************************
//
// Custom Action to set the WEBSITE_DESCRIPTION and other properties.
// It's done after CostFinalize, in case of uninstall, because
// we need those properties in order to uninstall IIRF.
//
//*****************************************************************************
function SetWebsitePropsForUninstall_CA() {
    try {
        LogMessage("SetWebsitePropsForUninstall_CA() ENTER");

        // Retrieve the site stored in the IIRF_SITE MSI property.  This
        // is set with a registry search in the start of the MSI.  It is
        // placed in the registry during a previous IIRF install.

        var website = Session.Property("IIRF_SITE");
        //
        // The value is:
        //  - W3SVC - indicates a server-wide install
        //  - W3SVC/1, W3svc/10398, etc - indicates install to a particular site
        //  - blank - indicates no install of filter
        //
        LogMessage("website name(" + website + ")");

        if (website == "") {
            // The filter binary was not installed. In this case,
            // WEBSITE_PORT is not used, but it must not be empty (I think).
            Session.Property("WEBSITE_PORT")        = "198";
        }
        else if (website != "W3SVC") {
            // IIRF is installed on a particular site
            var sites = GetWebSites();
            for (var i = 0; i < sites.length; i++) {
                var site = sites[i];
                // obj property                Examples
                // =======================================================
                // site.name                   W3SVC/1, W3SVC/12378398, etc
                // site.id                     1, 12378398, etc
                // site.description            "Default Web Site", "Site2", etc
                // site.bindings["http"].port  80, 8080, etc

                if (site.name == website) {
                    Session.Property("WEBSITE_DESCRIPTION") = site.description;
                    Session.Property("WEBSITE_PORT")        = site.bindings["http"].port;
                    Session.Property("WEBSITE_IP")          = site.bindings["http"].ip;
                    Session.Property("WEBSITE_HEADER")      = site.bindings["http"].hostname;
                }
            }
        }
        else {
            // IIRF is installed server-side
            // WEBSITE_PORT is not used, but it must not be empty (I think).
            // WEBSITE_DESCRIPTION is used in a <Condition>.
            Session.Property("WEBSITE_PORT")        = "199";
            Session.Property("WEBSITE_DESCRIPTION") = "";
        }

        LogMessage("SetWebsitePropsForUninstall_CA() EXIT (Ok)");
    }
    catch (exc1) {
        Session.Property("CA_EXCEPTION") = exc1.message ;
        LogException("SetWebsitePropsForUninstall", exc1);
        return MsiActionStatus.Abort;
    }
    return MsiActionStatus.Ok;
}

