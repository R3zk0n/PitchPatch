import sys


from modules.msft import msft_module
from modules.delta import *
import argparse

def search_kb_for_cve(cve):
    msft_class = msft_module()
    msft_class.get_kb_for_cve(cve)


if __name__ == '__main__':
    # Need to use arch to process and version such as Windows 8 or Windows 7
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--cve", help="CVE to search for")
    parser.add_argument("-a", "--arch", help="Architecture to search for", default="")
    parser.add_argument("-v", "--version", help="Windows version to use", default="")
    parser.add_argument("-d", "--download", help="Download Patch", default=False)
    args = parser.parse_args()
    # If no args parse print help
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
   
    elif args.cve is not None and args.download is not None:
        msft_class = msft_module()
        msft_class.odata_query_cve(args.cve, args.version, args.arch, args.download)
    else:
        msft_class = msft_module()
        msft_class.odata_query_cve(args.cve, args.version, args.arch, None)



# See PyCharm help at https://www.jetbrains.com/help/pycharm/
