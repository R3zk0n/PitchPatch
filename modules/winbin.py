from threading import Thread
from pathlib import Path
import subprocess
import datetime
import requests
import hashlib
import shutil
import json
import re
from rich import print
from rich.console import Console
from rich.table import Table

class UpdateNotFound(Exception):
    pass

class UpdateNotSupported(Exception):
    pass

class WinBinModules():
    def __init__(self) -> None:
        self.console = Console()

    def get_update(self, windows_version='11-21H2', update_kb=None):
        if windows_version is None:
            windows_version = '11-21H2'
        else:
            windows_version = windows_version
    

        search_query = update_kb or ""

        if windows_version == '11-21H2':
            package_windows_version = 'Windows 11'  # first Windows 11 version, no suffix
        elif '-' in windows_version:
            windows_version_split = windows_version.split('-')
            search_query += f' {windows_version_split[1]}'
            package_windows_version = f'Windows {windows_version_split[0]} Version {windows_version_split[1]}'
        else:
            search_query += f' {windows_version}'
            package_windows_version = f'Windows 10 Version {windows_version}'

        found_updates = self.search_for_updates(search_query)

        filter_regex = r'\bserver\b|\bDynamic Cumulative Update\b| UUP$'

        found_updates = [update for update in found_updates if not re.search(filter_regex, update[1], re.IGNORECASE)]

        # Replace the pattern, and if after the replacement the item exists, filter it.
        # For example, if there's both Cumulative and Delta, pick Cumulative.
        filter_regex_pairs = [
            [r'^(\d{4}-\d{2} )?Delta ', r'\1Cumulative '],
            [r'\bWindows 10 Version 1909\b', r'Windows 10 Version 1903'],
        ]

        found_update_titles = [update[1] for update in found_updates]
        filtered_updates = []
        for update in found_updates:
            update_title = update[1]
            matched = False
            for search, replace in filter_regex_pairs:
                update_title_sub, num_subs = re.subn(search, replace, update_title)
                if num_subs > 0 and update_title_sub in found_update_titles:
                    matched = True
                    break

            if not matched:
                filtered_updates.append(update)

        found_updates = filtered_updates
        print(found_updates)

        if len(found_updates) != 1:
            raise Exception(f'Expected one update item, found {len(found_updates)}')

        update_uid, update_title = found_updates[0]
        update_title_pattern = rf'(\d{{4}}-\d{{2}} )?(Cumulative|Delta) Update (Preview )?for {package_windows_version} for (?i:{config.updates_architecture})-based Systems \({update_kb}\)'
        assert re.fullmatch(update_title_pattern, update_title), update_title

        return update_uid, update_title


    def search_for_updates(self, search_terms):
        console = Console()
        # Updated
        console.print(search_terms)

        url = 'https://www.catalog.update.microsoft.com/Search.aspx'
        while True:
            html = requests.get(url, {'q': search_terms}).text
            if 'The website has encountered a problem' not in html:
                break

        if 'We did not find any results' in html:
            raise UpdateNotFound

        assert '(page 1 of 1)' in html  # we expect only one page of results

        p = r'<a [^>]*?onclick=\'goToDetails\("([a-f0-9\-]+)"\);\'[^>]*?>\s*(.*?)\s*</a>'
        matches = re.findall(p, html)

        p2 = r'<input id="([a-f0-9\-]+)" class="flatBlueButtonDownload\b[^"]*?" type="button" value=\'Download\' />'
        assert [uid for uid, title in matches] == re.findall(p2, html)

        return matches
    
    


        
