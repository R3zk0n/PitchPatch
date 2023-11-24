import json
import xml
from datetime import datetime

import requests
import xml.dom.minidom
from modules import table
import pyodata
import requests
from bs4 import BeautifulSoup
from modules.table import TableClass, DownloadTableClass

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

    async def download_kb(self, download_url):
        browser = await launch()
        page = await browser.newPage()


        await page.goto(download_url)
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
        response_json = json.loads(r.text)
        print(r.text)

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
                           print(download_url)
                        asyncio.get_event_loop().run_until_complete(self.download_kb(unique_download_urls.pop()))
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









