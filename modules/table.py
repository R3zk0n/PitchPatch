from rich import print
from rich.console import Console
from rich.table import Table

'''
This class is used to 

'''

class PatchClass:
    def __init__(self) -> None:
        self.console = Console()
        self.table = Table(show_header=True, header_style="bold white", show_lines=True)
        self.table.add_column("Title", style="bold white", header_style="bold white")
        self.table.add_column("Update", style="bold blue", justify="left", header_style="bold blue")
        self.table.add_column("UUID", style="cyan", justify="left", header_style="cyan")

    def table_output(self, Title, Update, UUID):
        self.table.add_row(Title, Update, UUID)

    def display_table(self):
        console = Console()
        console.print(self.table)
    

class DownloadTableClass:
    def __init__(self):
        self.console = Console()
        self.table = Table(show_header=True, header_style="bold white", show_lines=True)
        self.table.add_column("Title", style="bold white", header_style="bold white")
        self.table.add_column("OS", style="bold blue", justify="left", header_style="bold blue")
        self.table.add_column("Date", style="cyan", justify="left", header_style="cyan")
        self.table.add_column("Size", style="bold magenta", justify="left", header_style="bold magenta")
        self.table.add_column("Download", style="bold red", justify="left", header_style="bold red")

    def table_output(self, Update, OS, Date, Size, Download):
        self.table.add_row(Update, OS, Date, Size, Download)

    def display_table(self):
        console = Console()
        console.print(self.table)


'''
This class is used to to create and display the table for the after passing the Odata metadata information. 

'''
class TableClass:
    def __init__(self):
        self.console = Console()
        self.table = Table(show_header=True, header_style="bold white", show_lines=True)
        self.table.add_column("[white]CVE[/white]", style="bold white", header_style="bold white")
        self.table.add_column("Product", style="bold blue", justify="left", header_style="bold blue")
        self.table.add_column("Impact", style="cyan", justify="left", header_style="cyan")
        self.table.add_column("Release Date", style="bold magenta", justify="left", header_style="bold magenta")
        self.table.add_column("Base Score", style="bold red", justify="left", header_style="bold red")
        self.table.add_column("Vector String", header_style="yellow", style="yellow", justify="left")
        self.table.add_column("Download URLs", style="blue", no_wrap=True, header_style="bold blue")
        self.table.add_column("KB", style="red", no_wrap=True, header_style="red")
        self.table.add_column("Superceded KB", style="red", no_wrap=True, header_style="red")


    def table_output(self, cve, product, impact, release, base, vector, download_urls, kb, superceded_kb):
        download_urls_str = ', '.join(download_urls)
        self.table.add_row(cve, product, impact, release, base, vector, download_urls_str, kb, superceded_kb)



    def display_table(self):
        console = Console()
        console.print(self.table)
