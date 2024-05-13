# 2_compiling_dlls
This step will take the output of step 1 and identify target executables and target DLLs to be hijacked. We will compile our own DLLs, and prepare a script that will execute all target executables alongside its target DLLs.

## Steps

0. **Pre-requirements**:
    1. Copy the CSV files from step 1 to this folder (on your analysis machine);
    2. Ensure Docker is installed (e.g. `sudo apt install docker.io`), and;
    3. Install the Docker image (`docker build -t wietze/mingw-tools:1.0 .`)

1. **Find DLL exports**: Download [DLL Export Viewer](https://www.nirsoft.net/utils/dll_export_viewer.html) and run it on your Windows machine.
    1. Click File -> Select DLLs -> "Load functions from the following DLL file:" -> `c:\windows\system32\*.dll` -> OK.
    2. Save the output to `entrypoints.txt`, in the same folder as the CSV files.
2. **Compile DLLs**: Run `python3 generate_dlls.py` on your analysis machine. This will compile all target DLLs and generate `dll_hijack_test.ps1`.
3. **Copy files**: Copy the following to a user folder on your Windows machine (e.g. `c:\users\public\downloads\`):
    - The compiled DLLs;
    - `dll_hijack_test.ps1`; and
    - `run_executable.vbs`.
4. **Test DLLs**: Run `powershell -ep bypass -file ./dll_hijack_test.ps1` (as a regular user, NOT as administrator) on your Windows machine.


## Find DLL Exports
To maximise our chances, we're going to compile DLLs that have the same entrypoints as the original DLLs. To this end, we'll use DLL Export Viewer to get an overview of which entrypoints each orignal DLL exposes. Each function name and its ordinal are then replicated in our DLL.


## Compile DLLs
Using the above information, C code for our own DLLs is generated. Each function, as well as `DllMain`, will create a file formatted as `{processname}_{dllname}_{functionname}_{elevated}.txt` in `c:\users\public\downloads` when invoked. An example would be `winsat.exe_dxgi.dll_DllMain_1.txt`, which indicates that `winsat.exe` successfully loaded our `dxgi.dll` calling `DllMain`, in an elevated context. Similarly, `djoin.exe_wdscore.dll_CurrentIP_0.txt` indicates `djoin.exe` successfully loaded our `wdscore.dll` calling `CurrentIP`, in a normal (non-elevated) context.

A few things to note:
* For simplicity, DLLs written in C++ are skipped.
* DLLs exposing features that are referenced in `windows.h` and its dependencies will error (and are therefore skipped).
* Every successfully loaded DLL will always trigger `DllMain`, regardless of whether/what other entrypoints are called.


## Test DLLs
The final step is to copy each legitimate target application to a temp location, alongside each compiled DLL and determine which DLLs are successful.
The generated PowerShell script will:
* Create a temp folder;
* Copy all legitimate DLLs in the `system32` folder to the temp folder;
* Then, for every DLL that was successfully compiled:
    * Copy the compiled DLL to our temp folder (replacing the legitimate one);
    * Copy each associated (legitimate) target executable to the same folder;
    * Execute each copied executable; and
    * Clean up (delete DLL and executable, restore legitimate DLL).

As described in the previous step, this will generate `.txt` files in `c:\users\public\downloads\` indicating which DLL Hijacks were successful.

The temp folder is set to `c:\windows \system32` (note the space after `windows`) by default, in order to trigger UAC bypass. This is also the reason the `run_executable.vbs` file is required - PowerShell can't start processes in this folder, whilst VBScript can. For more details about this, see the original blog post.
