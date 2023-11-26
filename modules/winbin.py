from threading import Thread
from pathlib import Path
import subprocess
import datetime
import requests
import hashlib
import shutil
import json
import re
from rich.console import Console




class WinBinModules():
    def __init__(self) -> None:
        self.version = "0.0.1"
        self.name = "WinBinModules"
        self.console = console.Console()

    def get_update_from_kb(self, version, kb):
        search_query = kb
        if version == '11-21H2':
            package_windows_version = fr'Windows 11'  # first Windows 11 version, no suffix
        elif '-' in version:
            windows_version_split = version.split('-')
            search_query += f' {windows_version_split[1]}'
            package_windows_version = fr'Windows {windows_version_split[0]} Version {windows_version_split[1]}'
        else:
            search_query += f' {version}'
            package_windows_version = fr'Windows 10 Version {version}'

        find_updates = self.search_for_update(search_query)
    
    def search_for_update():
        


    


        
