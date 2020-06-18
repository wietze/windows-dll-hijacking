On Error Resume Next
Set Arg = WScript.Arguments
set wshshell = wscript.createobject("wscript.shell")
set objFSO = CreateObject("Scripting.FileSystemObject")
command = "c:\windows \system32\"&Arg(0)
Wscript.Echo """"&command&""""
wshshell.run(""""&command&"""")
