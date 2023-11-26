import json
import xml
from datetime import datetime

import requests
import xml.dom.minidom
from modules import table
from modules.table import PatchClass
import pyodata
import requests
from bs4 import BeautifulSoup
from modules.table import TableClass, DownloadTableClass
import re
import asyncio
from pyppeteer import launch


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
        
        


    async def search_for_update(self, download_url):
        Pclass = PatchClass()

        html = requests.get(download_url).text

        if 'The website has encountered a problem' not in html:
            pass

        if 'We did not find any results' in html:
            print("No results found")
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
            if size:
                uuid = size.group(1)
                size_data = size.group(2)
                if uuid not in uuid_to_data_mapping:
                    uuid_to_data_mapping[uuid] = {
                        'data': data,
                        'size': size_data
                    }
            else:
                size_data = ''

        for uuid, data_and_size in uuid_to_data_mapping.items():
            data = data_and_size['data']
            size = data_and_size['size']
            print(f"UUID: {uuid}")
            print(f"Data: {data}")
            print(f"Size: {size}")
            

    
    def get_update_download_url(self, update_uid):
        input_json = [{
            'uidInfo': update_uid,
        'updateID': update_uid
        }]

        url = 'https://www.catalog.update.microsoft.com/DownloadDialog.aspx'
        html = requests.post(url, {'updateIDs': json.dumps(input_json)}).text
        p = r'\ndownloadInformation\[\d+\]\.files\[\d+\]\.url = \'([^\']+)\';'
        matches = re.findall(p, html)
        print(matches)

                
            


            
    @DeprecationWarning
    async def download_kb(self, download_url):
        browser = await launch()
        page = await browser.newPage()


        await page.goto(download_url)
        # Check the content length of the response
        content_length = await page.evaluate('() => { return document.body.innerText.length; }')
        print(content_length)
        # Print the page content to the console
       # print(await page.content())
        download_size_xpath = "//td[contains(@class, 'resultspadding') and contains(@class, 'resultsSizeWidth')]/span"
        version_xpath = "//td[contains(@class, 'resultsbottomBorder') and contains(@class, 'resultspadding')][3]/text()"

        date_xpath = "//td[contains(@class, 'resultsbottomBorder') and contains(@class, 'resultspadding')][5]"

        # Use XPath to extract the content
        try:
            date_element = await page.waitForXPath(date_xpath, {'timeout': 600})
            date_text = await page.evaluate('(element) => element.textContent', date_element)

            element = await page.waitForXPath(version_xpath, {'timeout': 600})
            windows_server_version = await page.evaluate('(element) => element.textContent', element)

            # Download size
            element = await page.waitForXPath(download_size_xpath, {'timeout': 600})
            download_size = await page.evaluate('(element) => element.textContent', element)

            # XPath for the <a> element
            title = "//td[contains(@class, 'resultspadding')]/a"

            # Wait for the element to be available
            element = await page.waitForXPath(title)

            # We want the download button too so we can get the download URL
            button = "//input[@class='flatBlueButtonDownload focus-only']"
            button_element = await page.waitForXPath(button, {'timeout': 600})
            await button_element.click()
            print(download_url)
            # Wait for the new dialog page to open
            new_page = await browser.waitForTarget(lambda target: target.url().startswith('https://catalog.update.microsoft.com/DownloadDialog.aspx'), {'timeout': 600})
            dialog_page = await new_page.page()
            print(dialog_page)
            await browser.close()


       

            
           




            # Extract the text
            title = await page.evaluate('(element) => element.textContent', element)
            if title:
                DownloadTable = DownloadTableClass()
                DownloadTable.table_output(title.strip(), windows_server_version.strip(), date_text.strip(), download_size.strip(), download_url)
                element = await page.waitForXPath(download_size_xpath)
                download_size = await page.evaluate('(element) => element.textContent', element)
                DownloadTable.display_table()
                self.console.print("+"*1000)
            else:
                pass

        except Exception as e:
            pass


        #print(version_xpath)




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
      #  print(r.text)

        # Create Table
        table_class = table.TableClass()

        # Check if the response has data
        if 'value' in response_json and len(response_json['value']) > 0:
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
                    print(e)
                    continue



                for article in item.get('kbArticles', []):
                    supercedence = article.get('supercedence', "None")

                    if supercedence is None:
                        supercedence = "N/A"






                # Collect unique download URLs for this specific item
                unique_download_urls = {article['downloadUrl'] for article in item.get('kbArticles', []) if
                                        'downloadUrl' in article}



                kb_path = {url.split('q=')[-1] for url in unique_download_urls}
                kb_numbers_str = ', '.join(kb_path)

                # Add a row to the table for this item
                if download:
                    if len(unique_download_urls) > 0:
                        for download_url in unique_download_urls:
                        
                           #print(download_url)
                            content_length_check = requests.get(download_url)
                        # print Content length response to the console
                            response_length = content_length_check.headers.get('content-length')
                        # Theres gotta be a better way to do this, but for now i cant work it out, i am also tired. 
                            if response_length is not None and int(response_length) in range(10220, 10238):
                                pass
                            else:
                            # Print the text 
                            # print(download_ur
                                asyncio.get_event_loop().run_until_complete(self.search_for_update(download_url))
                                #asyncio.get_event_loop().run_until_complete(self.download_kb(download_url))
                        # print the unique download urls
                        
                    else:
                        pass
                        #table_class.table_output(cve, product, impact, fixed_data, base_score, vector_string, unique_download_urls, kb_numbers_str)
                else:
                     table_class.table_output(cve, product, impact, fixed_data, base_score, vector_string, unique_download_urls, kb_numbers_str, supercedence)

        else:
            print("No data available in the response.")

        # Display the table after processing all items
        table_class.display_table()
       # asyncio.get_event_loop().run_until_complete(self.download_kb(kb_numbers_str))









