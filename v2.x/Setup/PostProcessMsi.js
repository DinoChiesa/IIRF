// PostProcessMsi.js
// 
// Performs a post-build fixup of an msi to prettify the IIRF setup wizard.
//
// Tue, 24 Nov 2009  22:34
// 
// ==================================================================



function LogException(loc, exc1)
{
    WScript.StdErr.WriteLine("Exception [" + loc + "]");
    // for every property on the exception object
    for (var x in exc1)
    {
        if (x.toString() == "number")
            WScript.StdErr.WriteLine("e[" + x + "] = 0x" + decimalToHexString(exc1[x]));
        else
            WScript.StdErr.WriteLine("e[" + x + "] = " + exc1[x]);
    }
    WScript.Quit(1);
}


// Format a number as hex.  Quantities over 7ffffff will be displayed properly.
function decimalToHexString(number)
{
    if (number < 0)
        number = 0xFFFFFFFF + number + 1;
    return number.toString(16).toUpperCase();
}





// Constant values from Windows Installer
var msiOpenDatabaseModeTransact = 1;

if (WScript.Arguments.Length != 1)
{
    WScript.StdErr.WriteLine(WScript.ScriptName + ": Updates an MSI to move the custom action in sequence");
    WScript.StdErr.WriteLine("Usage: ");
    WScript.StdErr.WriteLine("  " + WScript.ScriptName + " <file>");
    WScript.Quit(1);
}

var filespec = WScript.Arguments(0);
WScript.Echo(WScript.ScriptName + " " + filespec);
var WshShell = new ActiveXObject("WScript.Shell");

var database = null;
try
{
    var installer = new ActiveXObject("WindowsInstaller.Installer");
    database = installer.OpenDatabase(filespec, msiOpenDatabaseModeTransact);
    // this will fail if Orca.exe has the same MSI already opened
}
catch (e1)
{
    LogException("open database", e1);
}

if (database==null) 
{
    WScript.Quit(1);
}


try
{
    WScript.Echo("Beautifying the setup wizard...");

    // For some reason, the checkbox has a gray background instead of white or transparent. 
    // I found no good explanation for this. 
    // http://www.dizzymonkeydesign.com/blog/misc/adding-and-customizing-dlgs-in-wix-3/
    // 
    // This step is a hack/workaround: it moves the checkbox to a gray area of the dialog
    // 
    var sql = "UPDATE `Control` SET `Control`.`Height` = '18', `Control`.`Width` = '170', `Control`.`Y`='243', `Control`.`X`='10' "  +
        "WHERE `Control`.`Dialog_`='ExitDialog' AND `Control`.`Control`='OptionalCheckBox'";
    var view = database.OpenView(sql);
    view.Execute();
    view.Close();

    // The text on the exit dialog is too close to the title.  This 
    // step moves the text down from Y=70 to Y=90, about one line. 
    sql = "UPDATE `Control` SET `Control`.`Y` = '90' " +
        "WHERE `Control`.`Dialog_`='ExitDialog' AND `Control`.`Control`='Description'";
    view = database.OpenView(sql);
    view.Execute();
    view.Close();

    // The progressbar is too close to the status text on the Progress dialog. 
    // This step moves the progressbar down from Y=115 to Y=118, about 1/3 line. 
    sql = "UPDATE `Control` SET `Control`.`Y` = '118' " +
        "WHERE `Control`.`Dialog_`='ProgressDlg' AND `Control`.`Control`='ProgressBar'";
    view = database.OpenView(sql);
    view.Execute();
    view.Close();

    // The StatusLabel and ActionText controls are too short on the Progress dialog,
    // which means the bottom of the text is cut off.  This step
    // increases the height from 10 to 16.
    sql = "UPDATE `Control` SET `Control`.`Height` = '16' " +
        "WHERE `Control`.`Dialog_`='ProgressDlg' AND `Control`.`Control`='StatusLabel'";
    view = database.OpenView(sql);
    view.Execute();
    view.Close();
    sql = "UPDATE `Control` SET `Control`.`Height` = '16' " +
        "WHERE `Control`.`Dialog_`='ProgressDlg' AND `Control`.`Control`='ActionText'";
    view = database.OpenView(sql);
    view.Execute();
    view.Close();

    database.Commit();

    WScript.Echo("done.");
}
catch(e)
{
    LogException("Editing", e);
}


