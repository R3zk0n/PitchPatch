from datetime import datetime
from dateutil.relativedelta import relativedelta
from Utils.Utils import calculate_one_month_back, get_previous_month_second_tuesday
from Utils.Utils import download, convert_date_format
import requests
import xml.dom.minidom
import os
import sys
import argparse
import subprocess
# It should extract about 5 files from the MSU file

class Extractor:
    def __init__(self) -> None:
        self.name = 'Extractor'
        self.description = 'Extracts the files from the update MSU file'
        self.author = "R3zk0n"
        self.version = "1.0"

    
    def check_os_system(msu_file):
        print("Checking the OS system")
        if os.name != 'nt':
            print("This script only works on Windows")
            sys.exit(1)
        else:
            print("OS is Windows")
            self.extract_msu_file(msu_file)


    def extract_msu_file(self, msu_file, output_dir):
        print("Extracting the MSU file")
        extract_cmd = "expand.exe " + "-F:* ", + msu_file + " ", output_dir
        os.system(extract_cmd)


    
    def extract_cab_file(self, cab_file, output_dir):
        print("Extracting the cab file")
        extract_cmd = "expand.exe " + "-F:* ", + cab_file + " ", output_dir
        
        os.system(extract_cmd)


    def run_patch_clean(folder_path):
        PATCH_CLEAN_PS1 =  """<#
                ================
                PATCHCLEAN.PS1
                =================
                Version 1.0 Patch Folder Cleaner by Greg Linares (@Laughing_Mantis)

                This Tool will go through the patch folders created by PatchExtract.PS1 and look for files created older 
                than 30 days prior to the current date and move these to a sub folder named "OLD" in the patch folders.

                This will help identify higher priority binaries that were likely updated in the current patch cycle window.

                =======    
                USAGE
                =======
                Powershell -ExecutionPolicy Bypass -File PatchClean.ps1 -Path C:\Patches\MS16-121

                This would go through the x86 folder and create a subfolder named C:\Patches\MS16-121\OLD\ and place
                older files and their folders in that directory.

                Files remaining in C:\Patches\MS16-121\ should be considered likely targets for containing patched binaries

                Empty folders are automatically cleaned and removed at the end of processing.

                -PATH <STRING:FolderPath> [REQUIRED] [NO DEFAULT]
                    Specified the folder that the script will parse and look for older files


                ================
                VERSION HISTORY
                ================

                Oct 20, 2016 - Version 1 - Initial Release


                ==========
                LICENSING
                ==========
                This script is provided free as beer.  It probably has some bugs and coding issues, however if you like it or find it 
                useful please give me a shout out on twitter @Laughing_Mantis.  Feedback is encouraged and I will be likely releasing 
                new scripts and tools and training in the future if it is welcome.


                -GLin

                #>

                Param
                (

                    [Parameter(ValueFromPipelineByPropertyName = $true)]
                    [ValidateNotNullOrEmpty()]
                    [string]$PATH = ""
                )


                Clear-Host

                if ($PATH -eq "")
                {
                    Throw ("Error: No PATH specified.  Specify a valid folder containing extracted patch files required. Generated by PatchExtract.ps1 ")
                
                }

                if (!(Test-Path $PATH))
                {
                    Throw ("Error: Invalid PATH specified '$PATH' does not exist.")
                }

                $OldDir = Join-Path -path $PATH -ChildPath "OLD"

                if (!(Test-Path $OldDir -pathType Container))
                {
                    New-Item $OldDir -Force -ItemType Directory
                    Write-Host "Making $OldDir Folder" -ForegroundColor Green
                }

                $FolderCount = 0
                $FileCount = 0
                $OldFiles = Get-ChildItem -Path $PATH -Recurse -File -Force -ErrorAction SilentlyContinue | Where{$_.LastWriteTime -lt (Get-Date).AddDays(-30)}


                foreach ($OldFile in $OldFiles)
                {
                    try
                    {
                        $FileCount++
                        $fileDir = (Get-Item($OldFile).DirectoryName)
                        $folderName = (Get-Item $fileDir ).Basename
                        $MoveDir = JOIN-Path -path $OldDir -ChildPath $folderName
                        if (!(Test-Path $movedir))
                        {
                            Write-Host "Creating $folderName to $OldDir" -ForegroundColor Green
                            New-Item $MoveDir -Force -ItemType Directory
                            $FolderCount++
                        }
                        Move-Item $OldFile.fullname $MoveDir -Force

                    }
                    catch
                    {
                        Write-Host ("Error Processing " + $OldFile.fullname) -ForegroundColor Red
                        Write-Host $_.Exception.Message
                        Write-Host $_.Exception.ItemName
                    }
                }

                #Clean Up Empty Folders

                $EmptyFolders = Get-ChildItem -Path $PATH  -Recurse| Where-Object {$_.PSIsContainer -eq $True} | Where-Object {$_.GetFiles().Count -eq 0 -and $_.GetDirectories().Count -eq 0 } | Select-Object FullName


                foreach ($EmptyFolder in $EmptyFolders)
                {
                    try
                    {
                        Write-Host ("Removing Empty Folder: " + $EmptyFolder.FullName) -ForegroundColor Yellow
                        Remove-Item -Path $EmptyFolder.FullName -Force
                    }
                    catch
                    {
                        Write-Host ("Error Removing: " + $EmptyFolder.Fullname) -ForegroundColor Red
                    }
                }

                Write-Host "=========================================================="

                Write-Host "High-Priority Folders within $PATH :"

                $NewFolders = Get-ChildItem -Path $PATH -Directory
                $HighCount = 0

                foreach ($folderName in $NewFolders)
                {
                    if (!($folderName -like "OLD"))
                    {
                        Write-Host $folderName
                        $HighCount++
                    }

                }

                Write-Host "=========================================================="

                Write-Host ("Low Priority Folders: " + $FolderCount)
                Write-Host ("Low Priority Files: " + $FileCount)
                Write-Host ("High Priority Folders: " + $HighCount)"""
        command = f"Powershell -ExecutionPolicy Bypass -Command -"
        try:
            completed_process = subprocess.run(
                [command], 
                input=PATCH_CLEAN_PS1 + f" -Path {folder_path}", 
                text=True, 
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            print("Script output:", completed_process.stdout)
        except subprocess.CalledProcessError as e:
            print(f"An error occurred: {e.stderr}")


        

if "__name__" == "__main__":
    print("This is the Extractor module");
    argparse = argparse.ArgumentParser(description="Extracts the files from the update MSU file")
    argparse.add_argument("--msu", help="The MSU file to extract")
    argparse.add_argument("--cab", help="The CAB file to extract")
    argparse.add_argument("--output", help="The output directory to extract the files to")
    args = argparse.parse_args()

    if args.msu and args.cab:
        print("Please only specify one of the following: --msu or --cab")
        sys.exit(1)
    elif args.msu:
        print("Extracting the MSU file")
        extractor = Extractor()
        extractor.extract_msu_file(args.msu, args.output)
    elif args.cab:
        print("Extracting the CAB file")
        extractor = Extractor()
        extractor.extract_cab_file(args.cab, args.output)
    else:
        print("Please specify the MSU or CAB file to extract")
        sys.exit(1)




