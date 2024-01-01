#!/usr/bin/env python
from textual.app import App, ComposeResult, RenderResult
from textual.widget import Widget
from textual.widgets import Static
from textual import events
from rich.table import Table
from textual.widgets import DataTable
import json

import sqlite3

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
        for data in rows:
            ip = data[0] if data[0] else ''
            mac = data[1] if data[1] else ''
            hostname = data[2] if data[2] else ''
            state = data[9] if data[9] else ''
            mac_vendor = data[10] if data[10] else ''
            whois = data[11] if data[11] else ''
            if state == 'up':
                table.add_row(ip, mac, hostname, state, mac_vendor, whois)
        conn.close()
        return None

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        # Close the connection
        if conn:
            conn.close()

class NetworkDiscover(App):
    CSS_PATH = "network_discover.tcss"
    #BINDINGS = [ ("u", "update", "Update")]

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
        yield DataTable()

    def on_mount(self) -> None:
        self.screen.styles.background = "darkblue"
        table = self.query_one(DataTable)
        existing_db_path = 'test4.sqlite'
        read_data_from_db_Datatable(existing_db_path, table)

    def on_key(self, event: events.Key) -> None:
        if event.key.isdecimal():
            self.screen.styles.background = self.COLORS[int(event.key)]


if __name__ == "__main__":
    app = NetworkDiscover()
    app.run()

