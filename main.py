import sys
from datetime import timedelta

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.

from modules.msft import msft_module
from modules.delta import *
import argparse
from modules.Collector import Collector
from modules.winbin import WinBinModules


def search_kb_for_cve(cve):
    msft_class = msft_module()
    msft_class.get_kb_for_cve(cve)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # Need to use arch to process and version such as Windows 8 or Windows 7
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--cve", help="CVE to search for")
    parser.add_argument("-a", "--arch", help="Architecture to search for", default="")
    parser.add_argument("-v", "--version", help="Windows version to use", default="Windows 10")
    parser.add_argument("-d", "--download", help="Download KB", default=False)
    parser.add_argument("-p", "--parse", help="Use the Database Module")
    parser.add_argument("-w", "--win", help="Use module")
    args = parser.parse_args()

    start_date = datetime(2017, 2, 1)
    end_date = datetime(2023, 2, 1)

    #if args.win is not None:
    #    WinBinModules_Class = WinBinModules()
    #    WinBinModules_Class.get_update(args.version, args.win)




    #f args.cve is None:
    #    print("Please provide a CVE to search for")
    if args.cve is not None and args.download is not None:
        msft_class = msft_module()
        msft_class.odata_query_cve(args.cve, args.version, args.arch, args.download)


    elif args.parse is not None:
        Collector_Class = Collector()
        current_date = start_date
        while current_date <= end_date:
            formatted_date = current_date.strftime("%d %b %Y")  # Format as "01 Feb 2017"
            Collector_Class.query_cvrf(formatted_date)
            current_date += timedelta(days=30)
        Collector_Class.query_cvrf("10 Jan 2017")  
    else:
        msft_class = msft_module()
        msft_class.odata_query_cve(args.cve, args.version, args.arch, None)

    

   



