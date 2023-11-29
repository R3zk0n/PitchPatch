import json
import xml
from datetime import datetime
from dateutil.relativedelta import relativedelta
from Utils.Utils import calculate_one_month_back, get_previous_month_second_tuesday
from Utils.Utils import download, convert_date_format
import requests
import xml.dom.minidom
from modules import table
from modules.table import PatchClass
import pyodata
import requests
from bs4 import BeautifulSoup
from modules.table import TableClass, DownloadTableClass
from modules.Collector import Collector
from modules.Collector import DatabaseClass
import re
import asyncio
from pyppeteer import launch
import os
visited_urls = set()

#MAIN TODO: Get the N-Day/1-day download to work
#TODO: Ensure that the productID mapping are not duplicated. 

'''
Per the recommendation from discord, this shuould levearge winbinindex to match the KB and download the "Patched and "Non patched" Version of the KB.
To Help.
'''

class Downloader:
    def __init__(self):
        self.name = 'Downloader'
        self.description = 'Microsoft Corporation'
        self.user_agent = """Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)"""
        self.browser = launch();
        self.winbinindex = "https://winbindex.m417z.com/"






class msft_module:
    def __init__(self):
        self.name = 'msft'
        self.description = 'Microsoft Corporation'
        self.user_agent = """Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"""

    async def handle_dialog(self, dialog_page):
        await dialog_page.waitForSelector('selector_of_the_content', {'visible': True})
        content = await dialog_page.evaluate('() => document.querySelector("selector_of_the_content").textContent')
        print(content)

    async def find_previous_version(self, updated_kb=None, last_kb=None):
        pass
        
    
    def calculate_one_month_back(self, input_date):
        input_datetime = datetime.strptime(input_date, "%B %d, %Y")
        one_month_back = input_datetime - relativedelta(months=1)
        result_date = one_month_back.strftime("%B %d, %Y")
        print(result_date)
        return result_date



    async def search_for_update(self, download_url):
        ran_once = False
        Pclass = PatchClass()

        html = requests.get(download_url).text

        if 'The website has encountered a problem' not in html:
            pass

        if 'We did not find any results' in html:
            pass
            return

        # Extracting matches using the first pattern
        p = r'<a [^>]*?onclick=\'goToDetails\("([a-f0-9\-]+)"\);\'[^>]*?>\s*(.*?)\s*</a>'
        matches = re.findall(p, html)

        # Extracting UUIDs for downloads
        p2 = r'<input id="([a-f0-9\-]+)" class="flatBlueButtonDownload\b[^"]*?" type="button" value=\'Download\' />'
        download_uuids = re.findall(p2, html)
        #print(html)

        # Extract data from each row, including the date
        p3 = r'<tr id="([a-f0-9\-]+_R\d+)"[^>]*>(.*?)</tr>'
        rows = re.findall(p3, html, re.DOTALL)
        uuid_to_data_mapping = {}

        for row_id, row_content in rows:
            data = re.findall(r'<td class="resultsbottomBorder resultspadding"[^>]*?>\s*(.*?)\s*</td>', row_content)
            size = re.search(r'<span id="([a-f0-9\-]+)_size">([^<]+)</span>', row_content)
            kb = re.search(r'(\d{4}-\d{2} [A-Za-z0-9\s()\[\]-]+ \(KB\d+\))', row_content)
            kb_num = re.search(r'\(KB[0-9]+\)', row_content)
            # Convert visited URLs to unique urls only

            if download_url not in visited_urls:
                visited_urls.add(download_url)
                

            #print(kb)
            # print full match of kb

            if size and kb:
                uuid = size.group(1)
                size_data = size.group(2)
                full_kb = kb.group(1)
                kb_num = kb_num.group(0)
                clean_kb = kb_num.strip("()")
                if uuid not in uuid_to_data_mapping:
                    uuid_to_data_mapping[uuid] = {
                        'data': data,
                        'size': size_data,
                        'KB': clean_kb,
                        'full_kb': full_kb
                    }
            else:
                size_data = ''

        for uuid, data_and_size_kb in uuid_to_data_mapping.items():
            data = data_and_size_kb['data']
            size = data_and_size_kb['size']
            full_kb = data_and_size_kb['full_kb']
            kb = data_and_size_kb['KB']
            # Extract the date from the full kb
            date = re.search(r'(\d{4}-\d{2})', full_kb)
            print(date.group(1))
            PclassTable = PatchClass()
            PclassTable.table_output(full_kb, size, uuid)
            PclassTable.display_table()
            self.get_update_download_url(uuid, kb=kb)


    
    def get_update_download_url(self, update_uid, kb):
        input_json = [{
            'uidInfo': update_uid,
        'updateID': update_uid
        }]

        url = 'https://www.catalog.update.microsoft.com/DownloadDialog.aspx'
        html = requests.post(url, {'updateIDs': json.dumps(input_json)}).text
        p = r'\ndownloadInformation\[\d+\]\.files\[\d+\]\.url = \'([^\']+)\';'
        matches = re.findall(p, html)
        dest_dir = f'output/{kb}'

        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir)
        download(urls=matches, dest_dir=dest_dir)

                
            


            
    @DeprecationWarning
    async def download_kb(self, download_url):
        pass




    def odata_query_cve(self, cve, product_keyword, architecture_keyword, download=None):
        params = {
            "$orderBy": "releaseDate desc",
            "$filter": f"cveNumber eq '{cve}' and contains(product, '{product_keyword}') and contains(product, '{architecture_keyword}')"
        }

        # Make the request
        url = "https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct"
        r = requests.get(url, params=params)

        print(r.url)
        response_json = json.loads(r.text)

        # Create Table
        table_class = table.TableClass()

        # Check if the response has data
        if 'value' in response_json and len(response_json['value']) > 0:
            # Create an empty list to store the data for all items
            table_data = []

            for item in response_json['value']:
                try:
                    release_date = item['releaseDate']
                    product = item['product']
                    cleaned_data = datetime.fromisoformat(release_date.rstrip('Z'))
                    fixed_data = cleaned_data.strftime("%d %b %Y")
                    impact = item['impact']
                    base_score = item['baseScore']
                    vector_string = item['vectorString']
                    vector_string = vector_string.replace("CVSS:3.0/", "")
                    vector_string = vector_string.replace("CVSS:3.1/", "")
                except Exception as e:
                    # We should add logging..
                    continue

                for article in item.get('kbArticles', []):
                    supercedence = article.get('supercedence', "None")

                    if supercedence is None:
                        supercedence = "N/A"

                # Collect unique download URLs for this specific item
                unique_download_urls = {article['downloadUrl'] for article in item.get('kbArticles', []) if 'downloadUrl' in article}

                kb_path = {url.split('q=')[-1] for url in unique_download_urls}
                kb_numbers_str = ', '.join(kb_path)
                get_patch = get_previous_month_second_tuesday(fixed_data)
                #DataBaseMaker = DatabaseClass()
                #DataBaseMaker.create_tables()
                #Collector_Class = Collector()
                #Collector_Class.query_cvrf(fixed_data)
                

                # Add a row to the table data for this item
                if download:
                    if len(unique_download_urls) > 0:
                        for download_url in unique_download_urls:
                            # Check if the URL has already been visited
                            if download_url not in visited_urls:
                                # Add the URL to the set of visited URLs
                                visited_urls.add(download_url)

                                # Check content length
                                content_length_check = requests.get(download_url)
                                response_length = content_length_check.headers.get('content-length')

                                # Perform content length check
                                if response_length is not None and int(response_length) in range(10220, 10238):
                                    pass
                                else:
                                    # Call the search_for_update function only once for each unique URL
                                    asyncio.get_event_loop().run_until_complete(self.search_for_update(download_url))
                        else:
                            pass
                else:
                    # Append the data for this item to the table_data lista
                    table_data.append([cve, product, impact, fixed_data, get_patch,base_score, vector_string, unique_download_urls, kb_numbers_str, supercedence])

            # After processing all items, display the table
            if not download:
                for row in table_data:
                    table_class.table_output(*row)
                table_class.display_table()
        else:
            pass

        
     










