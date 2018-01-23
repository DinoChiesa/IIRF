@echo OFF
if not EXIST %1 then goto USAGE

net stop w3svc
copy /y IsapiRewrite4.dll %1
copy /y IsapiRewrite4.pdb %1
net start w3svc
echo done.

goto STOPEXIT

:USAGE

echo Please provide a path where IsapiRewrite4.dll will be dropped.
echo.

:STOPEXIT
