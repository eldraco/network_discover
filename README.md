# Network discover
Network discover is a python tool to find and monitor which hosts are UP in a network.

Author: Sebastian Garcia, eldraco@gmail.com

# Install

```pip install -r requirements.txt```

# Usage

```python3 network_disoverer.py```

    - Put a network range in the input (IPv4 or IPv6).
    - Press Enter
    - The table will be updated automatically.
    - If you are not focusing on the Input (use TAB) you can also do 'u' for running nmap and updating the table.
    - You can quit with 'q' (focus on in the Input) or CTRL-C
    - If nmap is running in the background, exit will wait for it to finish. Force it if it takes too much.

# Goal
To have a free software tool that can show which computers are up in the local network in a clear and automatic way. Then it evolved to include more features.

# How it works
- Network discoverer uses the `textual` library to manage the whole screen, widgets, tables, styles, colors, keys, input, popups, etc. 
- In the background we run `nmap` with some parameters and we output the results in a file called nmap-result.xml.
- Then we use a modernization of the program nmapdb.py to convert it to SQLite.
- Network discoverer reads this SQLite to update the table.

# Files
    - network_discover.py: Main file.
    - network_discover.tcss: CSS styles for the widgets.
    - nmap-result.xml: Default XML output file for all nmap scans.
    - nmap.sqlite: SQLite DB with results of the scan.
    - nmapdb.py: Program to convert the nmap XML to SQLite (a modernization of https://github.com/ebsd/nmapdb)
    - nmapdb.sql: The SQL schema to create the DB.
    - requirements.txt

