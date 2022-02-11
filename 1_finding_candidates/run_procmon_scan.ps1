#Requires -RunAsAdministrator

if((Get-Item -Path '.\' -Verbose).FullName -Like '*windows\system32*'){
    throw "Please ensure your working folder is anything other than the System32 folder, e.g. a user folder"
}

if(!(Test-Path -Path .\procmon.exe -PathType Leaf)){
    throw "Could not find procmon.exe - download it from https://docs.microsoft.com/en-us/sysinternals/downloads/procmon and put it in this folder."
}

# Find all trusted executables in System32
$paths = Get-ChildItem c:\windows\system32 -File | ForEach-Object { if($_ -match '.+?exe$') {Get-AuthenticodeSignature $_.fullname} } | where {$_.IsOSBinary} | ForEach-Object {$_.path }
# Output dir of Procmon log files (.pml) as specified in the PMC files (requires editing of procmon_template.pmc)
$output_dir = "c:\users\public\downloads"
# Executing these executables causes trouble, let's just skip them
$skips = "*shutdown*","*logoff*","*lsaiso*","*rdpinit*","*wininit*","*DeviceCredentialDeployment*","*lsass*"

foreach ($path in $paths) {
    $executable = Split-Path $path -Leaf
    if(($skips | where {$process -Like $_}) -or !(Test-Path ("{0}.pmc"-f$executable) -PathType leaf)) { continue; }
    $executable
    # Copy target executable to current dir
    Copy-Item $path .\
    # Start Procmon monitoring
    $procmon = Start-Process ".\procmon.exe" -ArgumentList "/accepteula", "/loadconfig", ("{0}.pmc"-f$executable), "/quiet", "/minimized", "/runtime", "10" -PassThru
    # Give it 1 sec to get ready
    Start-Sleep 3;
    # Start our target executable
    $app = Start-Process cmd.exe -ArgumentList ("/c", $executable) -PassThru
    # Wait until Procmon process finishes (3 secs)
    Wait-Process -ID $procmon.ID
    # Kill target process if necessary
    if(!$app.HasExited -and $app.ID){
        Stop-Process -ID $app.ID -Force
    }
    # Convert Procmon recording to CSV
    $app = Start-Process ".\procmon.exe" -ArgumentList "/accepteula", "/loadconfig", ("{0}.pmc"-f$executable), "/quiet", "/minimized", "/openlog", ("{0}\log.pml"-f$output_dir), "/saveapplyfilter", "/saveas", ("{0}.csv"-f$executable) -PassThru
    Wait-Process -ID $app.ID;
    # Remove raw Procmon recording
    Remove-Item ("{0}\log.pml"-f$output_dir)
    # Remove target executable
    Remove-Item $executable
}
