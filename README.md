# R3D-SSH-Hunter
R3D SSH Hunter: The Ultimate SSH Key and Bad Guy Tracker 
SSH Hunter is a tool for cyber threat intelligence professionals to automate the search for exposed SSH keys across the internet using Shodan. With asynchronous scanning and persistent tracking of known threat groups, SSH Hunter helps streamline the identification and analysis of potentially malicious SSH keys and configurations.

1. Introduction
SSH Hunter is a tool designed for threat intelligence experts to aid in the discovery of exposed SSH keys. Utilizing the Shodan API, this tool allows asynchronous scanning to detect open SSH configurations, identify threat group affiliations, and filter out known benign entries, assisting in proactive threat detection.

2. Key Features
Asynchronous Scanning: Efficiently scan multiple IPs simultaneously with asyncio and aiohttp to maximize Shodan queries.
Threat Group Mapping: Tracks and maps IP addresses associated with known threat groups, stored in a JSON file (threat_groups.json) for persistent tracking.
Junk Hash Filtering: Filters out junk or benign hashes from search results based on a predefined list (junk_hashes.json).
Colored Output for Quick Analysis: Provides colored terminal outputs using Colorama for easier interpretation of results.
Data Persistence: Saves known threat groups and junk hashes for continuity across sessions.

3. Setup and Installation

Prerequisites: Python 3.7+, Shodan API Key, dependencies in requirements.txt.
Install required packages:

pip install -r requirements.txt

Configuration: Replace 'YOUR_SHODAN_API_KEY' in the script with your Shodan API key.

4. Usage
5. 
Run the script with:

python ssh_hunter-share.py

Function Descriptions:

load_threat_groups(): Loads threat group mappings from threat_groups.json.
load_junk_hashes(): Loads junk hashes from junk_hashes.json to filter out irrelevant results.

5. Contributing
Contributions are welcome, especially in expanding threat group mappings and enhancing filtering logic.

6. License
This project is open-source and available under the MIT License.
