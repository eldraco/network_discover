#!/usr/bin/env python
from textual.app import App, ComposeResult
from textual.widgets import Static
from textual import events
from textual.widgets import DataTable
from rich.text import Text
from textual.binding import Binding
from textual.widgets import Footer
from textual.widgets import Header
from textual import work
from textual.logging import TextualHandler
from textual.widgets import Input
from datetime import datetime
from textual.validation import Function, ValidationResult, Validator
from textual import on
import logging
import sqlite3
import subprocess
import ipaddress

logging.basicConfig(
    level="NOTSET",
    handlers=[TextualHandler()],
)

HELP = """Network Discover uses nmap in the background to find all the computers in the network you specified
          It can also remember each network and show the previous hosts discovered.
          It can also show the hosts that were found before but are not present now.
       """


def read_data_from_db_Datatable(db_path, table)-> None:
    """
    The main function to read the sqlite DB and add it to the table.
    table: the DataTable to add it
    """
    try:
        # Connect to the existing SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Execute a SELECT query to fetch data from the 'host' table
        cursor.execute("SELECT ip, mac, hostname, protocol, os_name, os_family, os_accuracy, os_gen, last_update, state, mac_vendor, whois FROM hosts")
        rows = cursor.fetchall()

        index = 1
        logging.info(f'{table._label_column_key.value}')

        # Data in DB is 0: ip, 1: mac, 2: hostname, 3: protocol, 4: os_name, 5: os_family, 6: os_accuracy, 7: os_gen, 8: last_update, 9: state, 10: mac_vendor, 11: whois
        for data in rows:
            ip = data[0] if data[0] else ''
            mac = data[1] if data[1] else ''
            hostname = data[2] if data[2] else ''
            state = data[9] if data[9] else ''
            mac_vendor = data[10] if data[10] else ''
            whois = data[11] if data[11] else ''
            if state == 'up':
                try:
                    this_row = table.get_row(mac)
                    # The row exists with this MAC. Update

                    # Are all rields equal? Should we update it or not?
                    if str(this_row[0]) == ip and str(this_row[1]) == mac and str(this_row[2]) == hostname and str(this_row[3]) == state and str(this_row[4]) == mac_vendor and str(this_row[5]) == whois:
                        # Everything is the same, dont update
                        #table.update_cell(mac, columns_key[6], '')
                        continue
                    
                    # Some fields differ, so replace the data
                    table.remove_row(mac)
                    table.add_row(
                            Text(str(ip), style="italic #03AC13", justify="right"), 
                            Text(str(mac), style="italic #03AC13", justify="right"), 
                            Text(str(hostname), style="italic #03AC13", justify="right"), 
                            Text(str(state), style="italic #03AC13", justify="right"), 
                            Text(str(mac_vendor), style="italic #03AC13", justify="right"), 
                            Text(str(whois), style="italic #03AC13", justify="right"), 
                            Text('Updated', style="italic #03AC13", justify="right"), 
                            Text(f'{datetime.now()}', style="italic #03AC13", justify="right"), 
                            label=index, 
                            key=mac)
                except:
                    # If the row is not there. Add it
                    #logging.info(f'Not there the mac: {mac}')
                    table.add_row(
                            Text(str(ip), style="italic #03AC13", justify="right"), 
                            Text(str(mac), style="italic #03AC13", justify="right"), 
                            Text(str(hostname), style="italic #03AC13", justify="right"), 
                            Text(str(state), style="italic #03AC13", justify="right"), 
                            Text(str(mac_vendor), style="italic #03AC13", justify="right"), 
                            Text(str(whois), style="italic #03AC13", justify="right"), 
                            Text('New', style="italic #03AC13", justify="right"), 
                            Text(f'{datetime.now()}', style="italic #03AC13", justify="right"), 
                            label=index, 
                            key=mac
                            )
                table.refresh_row(index)
                index += 1
        conn.close()

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        # Close the connection
        try:
            if conn:
                conn.close()
        except UnboundLocalError:
            pass

class HostsData(DataTable):
    """
    Our data table
    """
    def on_mount(self) -> None:
        self.cursor_type = 'row'
        self.add_columns("IP", "MAC", "Hostname", "State", "MAC Vendor", "WHOIS", "Status", "Last Update")
        # Get the data
        existing_db_path = 'nmap.sqlite'
        read_data_from_db_Datatable(existing_db_path, self)
        #self.timer = self.set_interval(5, read_data_from_db_Datatable(existing_db_path, self))
        #self.timer.resume()

class validate_iprange(Validator):
    def validate(self, value: str) -> ValidationResult:
        if self.is_iprange(value):
            return self.success()
        else:
            return self.failure("That's not an IP range.")

    @staticmethod
    def is_iprange(value: str)-> bool:
        try:
            if ipaddress.IPv4Network(value):
                return True
            else:
                return False
        except ValueError:
            return False

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
        Binding(key="u", action="update", description="Update the list"),
    ]

    def action_help(self):
        """Show and hide the help"""
        help = self.query_one(Static)
        if help.styles.display == "none":
            help.styles.display = "block"
        else:
            help.styles.display = "none"

    def action_update(self):
        """Update the list of hosts
        By running nmap again"""
        self.notify('Running nmap')
        input = self.query_one(Input)
        self.run_nmap(input)
        table = self.query_one(DataTable)
        existing_db_path = 'nmap.sqlite'
        read_data_from_db_Datatable(existing_db_path, table)
        self.notify("Hosts updated.")

    @work(thread=True)
    async def run_nmap(self, input)-> None:
        """
        Run nmap again
        #logging.info('calling nmap')
        """
        command = f'nmap -sn {input.value} -oX nmap-result.xml'
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        logging.info(result.stdout)

        command = 'python nmapdb.py -c nmapdb.sql -d nmap.sqlite nmap-result.xml'
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        logging.info(result.stdout)
    
    def compose(self) -> ComposeResult:
        yield Header()
        yield Input(placeholder="IP range to check", classes='input', restrict=r"[0123456789./]*", max_length=18, validate_on=["submitted"], 
                    validators=[
                    validate_iprange()  
            ])
        yield HostsData(zebra_stripes=True)
        yield Static(HELP, classes='help')
        yield Footer()

    @on(Input.Submitted)
    def show_invalid_reasons(self, event: Input.Changed) -> None:
        # Updating the UI to show the reasons why validation failed
        if not event.validation_result.is_valid:  
            self.notify(str(event.validation_result.failure_descriptions[0]))

    def on_mount(self) -> None:
        # Put titles
        self.title = "Network Discover"
        self.sub_title = "Find all computers UP in the network"
        # Set style
        self.screen.styles.background = "darkblue"

    COLORS = [
        "white",
        "red",
        "purple",
        "fuchsia",
        "olive",
        "yellow",
        "navy",
        "teal",
        "aqua",
        "black",
    ]
    def on_key(self, event: events.Key) -> None:
        if event.key.isdecimal():
            self.screen.styles.background = self.COLORS[int(event.key)]

if __name__ == "__main__":
    app = NetworkDiscover()
    app.run()

