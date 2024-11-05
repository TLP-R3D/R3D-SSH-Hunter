import shodan
import asyncio
import aiohttp
import ssl
import certifi
import json
from collections import defaultdict
import os
import pandas as pd
from colorama import Fore, Style, init

# Initialize colorama for colored outputs
init(autoreset=True)

# Replace 'YOUR_SHODAN_API_KEY' with your actual Shodan API key
API_KEY = 'API HERE'

# Initialize the Shodan API client
api = shodan.Shodan(API_KEY)

# File paths for persistence
THREAT_GROUP_FILE = 'threat_groups.json'
JUNK_HASH_FILE = 'junk_hashes.json'

# Load the threat group mappings from the file
def load_threat_groups():
    if os.path.exists(THREAT_GROUP_FILE):
        with open(THREAT_GROUP_FILE, 'r') as f:
            return json.load(f)
    return {}

# Load the junk hashes from the file
def load_junk_hashes():
    if os.path.exists(JUNK_HASH_FILE):
        with open(JUNK_HASH_FILE, 'r') as f:
            return set(json.load(f))  # Convert list back to set
    return set()

# Initialize threat groups and junk hashes
hash_threat_groups = load_threat_groups()
junk_hashes = load_junk_hashes()

# Dictionary to store banner hashes and their corresponding IPs (use a set to avoid duplicate IPs)
banner_hashes = defaultdict(set)

# Save the threat groups to a file
def save_threat_groups():
    with open(THREAT_GROUP_FILE, 'w') as f:
        json.dump(hash_threat_groups, f)
    print(f"{Fore.CYAN}Threat groups saved to {THREAT_GROUP_FILE}")

# Save the junk hashes to a file
def save_junk_hashes():
    with open(JUNK_HASH_FILE, 'w') as f:
        json.dump(list(junk_hashes), f)  # Convert set to list for JSON serialization
    print(f"{Fore.CYAN}Junk hashes saved to {JUNK_HASH_FILE}")

# ASCII Art for a cool banner
from colorama import Fore, Style

from colorama import Fore, Style

def show_banner():
    print(f"{Fore.LIGHTRED_EX}{Style.BRIGHT}")
    print("TTTTTTTTTTTTTTT  LLLLL             PPPPPPPPPPP")
    print("      TTT        LLLLL             PPPPP    PPP")
    print("      TTT        LLLLL             PPPPP    PPP")
    print("      TTT        LLLLL             PPPPPPPPPPP ")
    print("      TTT        LLLLL             PPPP        ")
    print("      TTT        LLLLLLLLLLLL      PPPP        ")
    print("      TTT        LLLLLLLLLLLL      PPPP        ")
    print("")
    print("RRRRRRRRRRR      33333333333333  DDDDDDDDDDDD")
    print("RRRR    RRRRR    33333333333333  DDDDD    DDDD")
    print("RRRR    RRRRR              3333  DDDD      DDD")
    print("RRRRRRRRRRR          3333333333  DDDD      DDD")
    print("RRRR    RRRRR         333333333  DDDD      DDD")
    print("RRRR    RRRRR              3333  DDDDD    DDDD")
    print("RRRR    RRRRR    33333333333333  DDDDDDDDDDDD")
    print("RRRR    RRRRR    33333333333333  DDDDDDDDDDDD")
    print("")
    print(" --- R3D SSH Hunter: The Ultimate SSH Key and Bad Guy Tracker ---")
    print(f"{Style.RESET_ALL}")

# Function to gather SSH banner hash for the IP from the Shodan search results
async def check_port_22_and_get_banner_hash(session, ip):
    print(f"{Fore.YELLOW}Checking IP: {ip} for port 22...{Style.RESET_ALL}")
    url = f"https://api.shodan.io/shodan/host/{ip}?key={API_KEY}"
    
    async with session.get(url) as response:
        if response.status == 200:
            result = await response.json()
            
            # Try to retrieve SSH banner hash from the result if port 22 is open
            for service in result.get('data', []):
                if service['port'] == 22:
                    # Look for the hash field
                    banner_hash = service.get('hash')
                    
                    if banner_hash:
                        # Ignore junk hashes
                        if banner_hash in junk_hashes:
                            print(f"{Fore.RED}Ignoring junk hash for IP {ip}: {banner_hash}{Style.RESET_ALL}")
                            return None, None
                        print(f"{Fore.GREEN}Found SSH banner hash for IP {ip}: {banner_hash}{Style.RESET_ALL}")
                        return banner_hash, ip
    print(f"{Fore.RED}No SSH banner found for IP {ip} or port 22 is closed.{Style.RESET_ALL}")
    return None, None

# Function to run a search query and then check for SSH on port 22
async def query_shodan(search_query):
    try:
        ssl_context = ssl.create_default_context(cafile=certifi.where())  # Use certifi's CA certificates

        print(f"{Fore.CYAN}Running search: {search_query}{Style.RESET_ALL}")

        results = api.search(search_query)
        print(f"{Fore.CYAN}Found {results['total']} devices using the query: {search_query}{Style.RESET_ALL}")

        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
            tasks = []
            for result in results['matches']:
                ip = result['ip_str']
                # Create a task for each IP to check if port 22 is open
                tasks.append(check_port_22_and_get_banner_hash(session, ip))
            responses = await asyncio.gather(*tasks)

            for banner_hash, ip in responses:
                if banner_hash:
                    banner_hashes[banner_hash].add(ip)

    except shodan.APIError as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

# Function to display the results in a table
def display_results():
    print(f"\n{Fore.BLUE}{Style.BRIGHT}Displaying results...\n{Style.RESET_ALL}")
    known_threats = []
    unknown_duplicates = []

    for banner_hash, ips in banner_hashes.items():
        threat_group = hash_threat_groups.get(str(banner_hash))  # Ensure string conversion for comparison
        if threat_group:
            known_threats.append({"Banner Hash": banner_hash, "Threat Group": threat_group, "IPs": list(ips)})
        elif len(ips) > 1:
            unknown_duplicates.append({"Banner Hash": banner_hash, "IPs": list(ips)})

    # Display known threats
    if known_threats:
        print(f"{Fore.GREEN}{Style.BRIGHT}Known Threat Actor Hashes:{Style.RESET_ALL}")
        df_threats = pd.DataFrame(known_threats)
        print(df_threats)

    # Display unknown duplicates
    if unknown_duplicates:
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}Duplicate Unknown Hashes:{Style.RESET_ALL}")
        df_unknown = pd.DataFrame(unknown_duplicates)
        print(df_unknown)

# Function to add a new hash and threat group to the dictionary
def add_new_hash():
    try:
        # Prompt user for the SSH banner hash (integer only, no "hash:" prefix)
        new_hash = int(input(f"{Fore.YELLOW}Enter the new SSH banner hash (integer only, without 'hash:' prefix): {Style.RESET_ALL}"))  
        threat_group = input(f"{Fore.YELLOW}Enter the associated threat group: {Style.RESET_ALL}")  # Associated threat group name

        # Check if the hash already exists
        if str(new_hash) in hash_threat_groups:
            print(f"{Fore.RED}Hash {new_hash} is already associated with {hash_threat_groups[str(new_hash)]}.{Style.RESET_ALL}")
        else:
            # Add new hash and associated threat group to the dictionary
            hash_threat_groups[str(new_hash)] = threat_group
            print(f"{Fore.GREEN}Added hash {new_hash} with threat group {threat_group}.{Style.RESET_ALL}")
            save_threat_groups()  # Save the updated threat group
    except ValueError:
        # Handle invalid input for hash
        print(f"{Fore.RED}Invalid hash value. Please enter a valid integer.{Style.RESET_ALL}")

# Function to add a "junk" hash to be ignored
def add_junk_hash():
    try:
        # Prompt user for the junk SSH banner hash (integer only)
        junk_hash = int(input(f"{Fore.YELLOW}Enter the SSH banner hash to mark as junk: {Style.RESET_ALL}"))
        
        # Check if the hash is already marked as junk
        if junk_hash in junk_hashes:
            print(f"{Fore.RED}Hash {junk_hash} is already marked as junk.{Style.RESET_ALL}")
        else:
            junk_hashes.add(junk_hash)
            print(f"{Fore.GREEN}Added hash {junk_hash} to the junk list.{Style.RESET_ALL}")
            save_junk_hashes()  # Save the updated junk hashes
    except ValueError:
        print(f"{Fore.RED}Invalid hash value. Please enter a valid integer.{Style.RESET_ALL}")

# Function to search by threat group in the library with a list of options
async def search_threat_group():
    if not hash_threat_groups:
        print(f"{Fore.RED}No threat groups available.{Style.RESET_ALL}")
        return
    
    # Display available threat groups
    print(f"{Fore.CYAN}{Style.BRIGHT}Available Threat Groups:{Style.RESET_ALL}")
    threat_group_list = list(set(hash_threat_groups.values()))  # Unique threat groups
    for idx, group in enumerate(threat_group_list):
        print(f"{Fore.GREEN}{idx + 1}. {group}{Style.RESET_ALL}")
    
    try:
        # Prompt the user to choose a threat group by number
        choice = int(input(f"{Fore.YELLOW}Select a threat group by number (1-{len(threat_group_list)}): {Style.RESET_ALL}"))
        if 1 <= choice <= len(threat_group_list):
            selected_group = threat_group_list[choice - 1]
            print(f"{Fore.GREEN}Selected threat group: {selected_group}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")
            return
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
        return
    
    # Search for hashes associated with the selected threat group
    matched_hashes = [hash_ for hash_, group in hash_threat_groups.items() if group == selected_group]
    
    if not matched_hashes:
        print(f"{Fore.RED}No hashes found for the threat group: {selected_group}{Style.RESET_ALL}")
        return
    
    print(f"{Fore.CYAN}Found hashes for {selected_group}: {matched_hashes}{Style.RESET_ALL}")
    
    for hash_ in matched_hashes:
        # Search for each hash
        search_query = f"hash:{hash_}"  # Correctly use "hash:" instead of "ssh.hash:"
        await query_shodan(search_query)

# Main menu with fancy art and color
def main_menu():
    show_banner()  # Show cool ASCII art banner
    print(f"{Fore.BLUE}{Style.BRIGHT}\nMenu:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}1. Enter custom search query (e.g., product:cobalt, org:fly, etc.)")
    print(f"{Fore.CYAN}2. Search by specific SSH banner hash (e.g., hash:-12345678)")
    print(f"{Fore.CYAN}3. Add a new SSH banner hash and associated threat group")
    print(f"{Fore.CYAN}4. Search for IPs by threat group name")
    print(f"{Fore.CYAN}5. Mark a hash as junk (to be ignored in future results){Style.RESET_ALL}")
    
    choice = input(f"{Fore.YELLOW}Enter your choice (1, 2, 3, 4, or 5): {Style.RESET_ALL}")

    if choice == '1':
        search_query = input(f"{Fore.YELLOW}Enter your Shodan search query: {Style.RESET_ALL}")
        return search_query, False
    elif choice == '2':
        specific_hash = input(f"{Fore.YELLOW}Enter the SSH banner hash: {Style.RESET_ALL}")
        search_query = f"hash:{specific_hash}"  # Correctly use "hash:" for querying hashes
        return search_query, False
    elif choice == '3':
        add_new_hash()
        return None, None
    elif choice == '4':
        asyncio.run(search_threat_group())
        return None, None
    elif choice == '5':
        add_junk_hash()
        return None, None
    else:
        print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")
        return None, None

# Main entry point
if __name__ == "__main__":
    search_query, _ = main_menu()

    if search_query:
        asyncio.run(query_shodan(search_query))
        display_results()
