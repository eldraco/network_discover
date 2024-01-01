#!/usr/bin/env python
from textual.app import App, ComposeResult, RenderResult
from textual.widget import Widget
from textual.widgets import Static
from textual import events
from rich.table import Table
from textual.widgets import DataTable
from rich.text import Text
from textual.binding import Binding
from textual.widgets import Footer
from textual.widgets import Header
import sqlite3

HELP = """Network Discover uses nmap in the background to find all the computers in the network you specified
          It can also remember each network and show the previous hosts discovered.
          It can also show the hosts that were found before but are not present now.
       """

def read_data_from_db_Datatable(db_path, table)-> None:
    try:
        # Connect to the existing SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Execute a SELECT query to fetch data from the 'host' table
        cursor.execute("SELECT ip, mac, hostname, protocol, os_name, os_family, os_accuracy, os_gen, last_update, state, mac_vendor, whois FROM hosts")
        rows = cursor.fetchall()

        table.add_columns("IP", "MAC", "Hostname", "State", "MAC Vendor", "WHOIS")

        # Data in DB is 0: ip, 1: mac, 2: hostname, 3: protocol, 4: os_name, 5: os_family, 6: os_accuracy, 7: os_gen, 8: last_update, 9: state, 10: mac_vendor, 11: whois
        index = 0
        for data in rows:
            ip = data[0] if data[0] else ''
            mac = data[1] if data[1] else ''
            hostname = data[2] if data[2] else ''
            state = data[9] if data[9] else ''
            mac_vendor = data[10] if data[10] else ''
            whois = data[11] if data[11] else ''
            key = 'mac'
            if state == 'up':
                table.add_row(
                        Text(str(ip), style="italic #03AC13", justify="right"), 
                        Text(str(mac), style="italic #03AC13", justify="right"), 
                        Text(str(hostname), style="italic #03AC13", justify="right"), 
                        Text(str(state), style="italic #03AC13", justify="right"), 
                        Text(str(mac_vendor), style="italic #03AC13", justify="right"), 
                        Text(str(whois), style="italic #03AC13", justify="right"), 
                        label=index, 
                        key=mac)
                index += 1
        conn.close()

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        # Close the connection
        if conn:
            conn.close()


class NetworkDiscover(App):
    CSS_PATH = "network_discover.tcss"

    BINDINGS = [
        Binding(key="q", action="quit", description="Quit the app"),
        Binding(
            key="question_mark",
            action="help",
            description="Show help screen",
            key_display="?",
        ),
        Binding(key="delete", action="delete", description="Delete the thing"),
        Binding(key="j", action="down", description="Scroll down", show=False),
    ]

    def action_help(self):
        """Show and hide the help"""
        help = self.query_one(Static)
        if help.styles.display == "none":
            help.styles.display = "block"
        else:
            help.styles.display = "none"


    COLORS = [
        "white",
        "maroon",
        "red",
        "purple",
        "fuchsia",
        "olive",
        "yellow",
        "navy",
        "teal",
        "aqua",
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable()
        yield Static(HELP, classes='help')
        yield Footer()

    def on_mount(self) -> None:
        self.notify("Welcome to this App!.")
        self.title = "Network Discover"
        self.sub_title = "Find all computers UP in the network"
        self.screen.styles.background = "darkblue"
        table = self.query_one(DataTable)
        table.cursor_type = 'row'
        existing_db_path = 'test4.sqlite'
        read_data_from_db_Datatable(existing_db_path, table)

    def on_key(self, event: events.Key) -> None:
        if event.key.isdecimal():
            self.screen.styles.background = self.COLORS[int(event.key)]



if __name__ == "__main__":
    app = NetworkDiscover()
    app.run()

