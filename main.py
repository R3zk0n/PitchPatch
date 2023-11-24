# This is a sample Python script.
import sys

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.

from modules.msft import msft_module
from modules.delta import *
import argparse

def search_kb_for_cve(cve):
    msft_class = msft_module()
    msft_class.get_kb_for_cve(cve)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # Need to use arch to process and version such as Windows 8 or Windows 7
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--cve", help="CVE to search for")
    parser.add_argument("-a", "--arch", help="Architecture to search for", default="")
    parser.add_argument("-v", "--version", help="Windows version to use", default="")
    parser.add_argument("-d", "--download", help="Download KB", default=False)
    args = parser.parse_args()
    if args.cve is None:
        print("Please provide a CVE to search for")
    elif args.cve is not None and args.download is not None:
        msft_class = msft_module()
        msft_class.odata_query_cve(args.cve, args.version, args.arch, args.download)
    else:
        msft_class = msft_module()
        msft_class.odata_query_cve(args.cve, args.version, args.arch, None)



# See PyCharm help at https://www.jetbrains.com/help/pycharm/
