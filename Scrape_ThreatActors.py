import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style
import re
import time
import random
import pandas as pd
import base64

# Get country code
while True:
    country = input(Fore.LIGHTMAGENTA_EX + "[+] Enter the Country code.\n[+] Example(cn,ru,ir)\n=========> " + Style.RESET_ALL).lower()

    if len(country) != 2:
        print(Fore.RED + "[+] Country code should be exactly two letters. Please try again." + Style.RESET_ALL)
        continue
    else:
        break

agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.1000.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36 Edg/93.0.961.52',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.9999.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.9999.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.9999.0 Safari/537.36',]

user_agent = random.choice(agents) # Randomize user agents

r = requests.get("https://malpedia.caad.fkie.fraunhofer.de/actors", headers={'User-Agent': user_agent})

soup = BeautifulSoup(r.content, 'html.parser') # Parse html data that we recieve from GET request


# Search for all span tags with the specific flag-icon and flag-icon-cn classes
flag_icons_cn = soup.find_all('span', {'class': lambda x: x and f'flag-icon-{country}' in x}) # grab "/actor/" for actor name to append to url

if len(flag_icons_cn) == 0:
    print(Fore.RED + f"[+] No data available for that country code: {country}." + Style.RESET_ALL)
    exit()

# Initialize list to store all the data-href attributes
data_hrefs = []

# Iterate through each flag icon
for flag_icon in flag_icons_cn:
    # Traverse up to the parent <tr> element
    parent_tr = flag_icon.find_parent('tr', class_='clickable-row')
    # Extract data-href attribute and append to list
    if parent_tr and 'data-href' in parent_tr.attrs:
        data_hrefs.append(parent_tr['data-href'])

actors = [x.replace('/actor/', '') for x in data_hrefs] # Just print actors name, get rid of "/actor/"
actors_list = ' \n'.join(actors) # print to screen on newline

print(Fore.GREEN + f"\n[+] List of actors for {country}: \n" + Style.RESET_ALL, Style.BRIGHT + actors_list + Style.RESET_ALL)

url = []

for i in data_hrefs:
    url.append(f"https://malpedia.caad.fkie.fraunhofer.de{i}") # list of URL to query for aliases

print(Fore.GREEN + f"\n[+] Threat Actor URLs for {country}" + Style.RESET_ALL)
print(Style.BRIGHT + ' \n'.join(url), "\n", Style.RESET_ALL)
print(Fore.GREEN + f"[+] Looking for {country} Threat Actor Aliases")

def get_them_all(): # Get actor aliases
    get_all_names = []

    for i in url:
        time.sleep(random.randint(10,20))
        
        r = requests.get(i, headers={'User-Agent': user_agent})
        soup = BeautifulSoup(r.content, 'html.parser')

        aka_divs = soup.find_all('div', string=re.compile(r'aka:'))  # Changed to find_all

        actor_aliases = []

        if aka_divs:
            for aka_div in aka_divs:
                aka_text = aka_div.string.strip().replace("aka:", "").strip()
                actor_aliases.append(aka_text)
                print(aka_text)
            get_all_names.append(actor_aliases)
        else:
            print(Fore.LIGHTMAGENTA_EX + "Couldn't find the aka information for URL:", i + Style.RESET_ALL)  # Changed actor_url to i
            get_all_names.append(["No alias"])  # Add a placeholder for actors without aliases

    # Flatten the list and create pairs
    combined_list = [(actor, alias) for actor, aliases in zip(actors, get_all_names) for alias in aliases]
    
    # Save to a DataFrame and then to CSV
    df = pd.DataFrame(combined_list, columns=['Actor', 'Alias'])
    df.to_csv(f'combined_actors_and_aliases_{country}.csv', index=False) # save output to a csv file

    return combined_list

def flattened_list_func(comb_list):
    flattened_list = []
    for tup in comb_list:
        flattened_list.append(tup[0])  # Appending the first string
        for item in tup[1].split(", "):  # Splitting the second string by ", " and appending each item
            flattened_list.append(item)

    return flattened_list

def feedly_filter(flat_list):
 
    search = ''

    for i in flat_list:
        search += ',{"text":"' + i + '"}'

    feedly_filter = '{"layers":[{"parts":[{"type":"customKeyword"'+search+'],"salience":"mention","searchHint":"","type":"matches"}],"bundles":[]}' # create feedly filter

    count = 0
    removed = False  # A flag to indicate if the 4th '{' has been removed

    new_feedly_filter = '' # need to remove 4th instance of "{" and only the 4th instance
    for char in feedly_filter:
        if char == '{':
            count += 1
        if count == 4 and not removed:  
            removed = True  
            continue  
        new_feedly_filter += char

    new_feedly_filter = new_feedly_filter.replace(',{"text":"No alias"}', '') # Get rid of the "No alias" Tuple porttion from combined in feedly filter

    encoded_filter = base64.b64encode(new_feedly_filter.encode()).decode() # encode feedly filter to b64 

    feedly_filter_url = f"https://feedly.com/i/powerSearch/in?options={encoded_filter}" # create feedly url

    print(Fore.GREEN+"\n[+] Your cusstom Feedly Filter URL:"+Style.RESET_ALL, Style.BRIGHT+feedly_filter_url+Style.RESET_ALL,"\n\n",Fore.GREEN+"[+] Filter output Clear Text:" + Style.RESET_ALL,Style.BRIGHT + new_feedly_filter + Style.RESET_ALL,"\n")

combined_list = get_them_all()  
flattened_list = flattened_list_func(combined_list)  
feedly_filter(flattened_list)  
