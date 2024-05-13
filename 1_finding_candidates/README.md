# 1_finding_candidates
This step will generate CSV files for each process, containing every DLL loaded by that process. This will tell us which DLLs are searched for in the path of the executable rather than System32 itself, and are therefore DLL Hijack candidates.

## Steps
1. **Generate PMC files**: Run `python3 generate_pmc_files.py` to generate PMC files that will be used by Procmon.
2. **Copy files**: Copy the following to a user folder on your Windows machine (e.g. `c:\users\public\downloads\`):
    - The generated PMC files;
    - `run_procmon_scan.ps1`; and
    - `procmon.exe`, which can be downloaded [here](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon). NOTE: the template file in the repository has been generated using Procmon v3.96.
3. **Start recording**: Run `powershell -ep bypass -file run_procmon_scan.ps1` as administrator on your Windows machine.

## PMC file generation
Why do we need separate PMC files for each process we're interested in? You could configure Procmon to look for any DLL load, run all target executables from a temp location, and process all detected DLL loads for all target executables at once. It turns out that with background processes running, this will be rather noisy and false positive prone.

Therefore, we will create Procmon configuration files (PMC) for each of our target binaries. However, PMC files are in an undocumented binary format: generating PMC files therefore requires some hex editing. Fortunately this can be automated, as can be seen in `generate_pmc_files.py`.

## Procmon monitoring
The PowerShell script in the last step, `run_procmon_scan.ps1`, will for every executable that is in scope:
* Copy the legitimate executable to the user folder;
* Start Procmon with the prepared PMC (config) file;
* Start the copied version of the legitimate executable;
* Export the found DLL loads to a CSV file; and
* Clean up (kill processes, delete copied executable and raw log file).

The generated CSV files will be parsed in the next step to analyse which DLLs are targets.
