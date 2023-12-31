import os
import json
import xml
import datetime
from dateutil.relativedelta import relativedelta
import requests
import xml.dom.minidom
from modules import table
from modules.table import PatchClass
import pyodata
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor
import signal
from functools import partial
from threading import Event
from typing import Iterable
from urllib.request import urlopen


from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

done_event = Event()


def handle_sigint(signum, frame):
    done_event.set()


signal.signal(signal.SIGINT, handle_sigint)

progress = Progress(
    TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
    BarColumn(bar_width=None),
    "[progress.percentage]{task.percentage:>3.1f}%",
    "•",
    DownloadColumn(binary_units=False),
    "•",
    TransferSpeedColumn()
    )


def convert_date_format(date_string):
    try:
        # Parse the input date string into a datetime object
        input_date = datetime.datetime.strptime(date_string, "%d %b %Y")

        # Format the datetime object as "YYYY-Mar" and return it
        output_date = input_date.strftime("%Y-%b")
        return output_date
    except ValueError:
        return "Invalid date format. Please use the format 'dd Mon yyyy' (e.g., '14 Mar 2017')."


def remove_namespace_prefix(element_name):
    return element_name.split('}')[-1]

def get_previous_month_second_tuesday(given_date):
    # Convert the given date to a datetime object
    given_date = datetime.datetime.strptime(given_date, "%d %b %Y")

    # Calculate the year and month of the given date
    year = given_date.year
    month = given_date.month

    # Calculate the first day of the current month
    first_day_of_current_month = datetime.datetime(year, month, 1)

    # Calculate the weekday of the first day of the current month (0 for Monday, 1 for Tuesday, ..., 6 for Sunday)
    first_day_weekday = first_day_of_current_month.weekday()

    # Calculate the difference in days to reach the second Tuesday of the current month
    days_to_second_tuesday = (7 - first_day_weekday + 1) + 7  # Adding 7 to skip the first Tuesday

    # Calculate the date of the second Tuesday of the current month
    second_tuesday = first_day_of_current_month + datetime.timedelta(days=days_to_second_tuesday)

    # Calculate the date of the second Tuesday of the previous month
    previous_month = month - 1 if month > 1 else 12  # Handle December as the previous month
    previous_month_year = year if month > 1 else year - 1  # Handle year change

    # Initialize the date for the second Tuesday of the previous month
    previous_month_second_tuesday = datetime.datetime(previous_month_year, previous_month, 1)

    # Find the second Tuesday of the previous month
    while previous_month_second_tuesday.weekday() != 1:  # 1 represents Tuesday
        previous_month_second_tuesday += datetime.timedelta(days=1)

    # Adjust the date to be exactly one week before the provided date
    previous_month_second_tuesday += datetime.timedelta(weeks=1)

    return previous_month_second_tuesday.strftime("%d %b %Y")


def calculate_one_month_back(input_date):
    input_datetime = datetime.strptime(input_date, "%B %d, %Y")
    one_month_back = input_datetime - relativedelta(months=1)
    result_date = one_month_back.strftime("%B %d, %Y")
    print(result_date)
    return result_date


def copy_url(task_id: TaskID, url: str, path: str) -> None:
    """Copy data from a url to a local file."""
    progress.console.log(f"Requesting {url}")
    response = urlopen(url)
    # This will break if the response doesn't contain content length
    progress.update(task_id, total=int(response.info()["Content-length"]))
    with open(path, "wb") as dest_file:
        progress.start_task(task_id)
        for data in iter(partial(response.read, 32768), b""):
            dest_file.write(data)
            progress.update(task_id, advance=len(data))
            if done_event.is_set():
                return
    progress.console.log(f"Downloaded {path}")

def download(urls: Iterable[str], dest_dir: str):
    """Download multiple files to the given directory."""

    with progress:
        with ThreadPoolExecutor(max_workers=4) as pool:
            for url in urls:
                filename = url.split("/")[-1]
                dest_path = os.path.join(dest_dir, filename)
                task_id = progress.add_task("download", filename=filename, start=False)
                pool.submit(copy_url, task_id, url, dest_path)






def get_update(windows_version, update_kb):
    search_query = update_kb

    if windows_version == '11-21H2':
        package_windows_version = fr'Windows 11'  # first Windows 11 version, no suffix
    elif '-' in windows_version:
        windows_version_split = windows_version.split('-')
        search_query += f' {windows_version_split[1]}'
        package_windows_version = fr'Windows {windows_version_split[0]} Version {windows_version_split[1]}'
    else:
        search_query += f' {windows_version}'
        package_windows_version = fr'Windows 10 Version {windows_version}'

    search_query += f' {config.updates_architecture}'

    found_updates = search_for_updates(search_query)

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

    if len(found_updates) != 1:
        raise Exception(f'Expected one update item, found {len(found_updates)}')

    update_uid, update_title = found_updates[0]
    update_title_pattern = rf'(\d{{4}}-\d{{2}} )?(Cumulative|Delta) Update (Preview )?for {package_windows_version} for (?i:{config.updates_architecture})-based Systems \({update_kb}\)'
    assert re.fullmatch(update_title_pattern, update_title), update_title

    return update_uid, update_title