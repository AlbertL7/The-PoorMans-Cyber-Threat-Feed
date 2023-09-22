# The PoorMans Cyber Threat Feed

Harness the power of open-source intelligence by leveraging this script to automatically scrape and curate a list of cyber threat actors and the latest Malware. Designed to tap into the vast data pool of malpedia.caad.fkie.fraunhofer.de.

When integrated with Feedly, this tool aids in building a comprehensive threat intelligence database by collecting the latest Indicators of Compromise (IoCs), Tactics, Techniques, and Procedures (TTPs), and vulnerabilities from open-source intelligence performed by the latest threat acotors. This enables organizations and individuals to stay informed about emerging threats and enhance their security posture by proactively addressing potential vulnerabilities.

The intended use is to run these programs probably once a week to get a comprehensive overview of the latest threat actors and malware. This will enable you to update the Feedly filter as needed or perform VirusTotal retro hunts based on the yara rules found for the malware you are investigaing.  

# Malware Hunter

## Overview

The Malware Threat Intel Builder is a Python-based tool designed to gather and analyze information about malware from various sources. It integrates with Feedly to provide AI feeds in Pro+ and uses Malpedia for information retrieval. The tool is capable of querying malware data, displaying descriptions, and showing Yara rules for selected malware. It also provides options to create Feedly filters in both URL encoded and clear text formats. 

## Features

- Malware Querying: Allows users to query a specific amount of malware, displayed from newest to oldest.
- Description Display: Provides detailed descriptions for the selected malware.
- Yara Rule Display: Shows Yara rules for selected malware.
- Feedly Filter Creation: Generates Feedly filters in URL encoded and clear text formats.
- Silent Mode: Suppresses default output.
- User-Agent Randomization: Uses different user agents for making requests to avoid blocking.
- Data Sorting: Sorts malware data based on the last updated date.
- User Interaction: Allows users to select malware interactively and decide whether to continue exploring other malware.

## Usage

The tool can be run from the command line using various arguments to customize its behavior. Below are the available arguments:

--get_malware <int>: Amount of Malware to Query, displayed from newest to oldest. Default is 10.
--u: Generates an Encoded Feedly Filter URL.
--ct: Generates a Feedly filter in clear text.
--d: Displays the description for the selected malware.
--y: Displays Yara rule(s) for selected malware.
--s: Silent mode, suppresses default output. Valid only when --u, --ct, --d, or --y is used.

## Example
```
python main.py --get_malware 5 --u --d
This command will query the 5 newest malwares, generate an encoded Feedly filter URL, and display the description for the selected malware.
```

## Installation

Clone the repository:

`git clone <repository-url>`
Navigate to the project directory:
`cd <project-directory>`
Install the required libraries:
`pip install -r requirements.txt`
## Dependencies

- BeautifulSoup
- Requests
- Pandas
- Base64
- Datetime
- Random
- Sys
- Argparse
  
## Functionality Overview

1. main(): The main function parses command-line arguments and calls the appropriate functions based on the provided arguments.
2. top_malware_strains(): Makes requests to Malpedia to get the top malware strains and returns sorted malware data.
3. user_select_malware(): Allows the user to interactively select malware and calls functions to display descriptions or Yara rules based on user input.
4. get_malware_description(): Retrieves and displays the description of the selected malware.
5. get_malware_yara(): Retrieves and displays the Yara rule of the selected malware.
6. URL_Encoded_feedly_filter(): Generates and prints the URL encoded Feedly filter.
7. clear_text_feedly_filter(): Generates and prints the clear text Feedly filter.

## Contribution

Feel free to fork the project and submit pull requests for any enhancements or bug fixes. If you encounter any issues or have suggestions for improvements, please open an issue in the repository.

## Use Case Example 1 Get top 15 most recent malware and create feedly filter
![image](https://github.com/AlbertL7/The-PoorMans-Cyber-Threat-Feed/assets/71300144/c290bb15-a63b-456e-bc95-12f40ec252a9)

## Use Case Example 2 grab yara rule and description for VirusTotal retro hunt. If the malware has more than one yara rule, all yara rules will be displayed. 
![image](https://github.com/AlbertL7/The-PoorMans-Cyber-Threat-Feed/assets/71300144/78aff5aa-48ba-4d6f-a842-0a1497839edb)

## Use Case Example 3 quickly query all yara and descriptions from originally grabbed malware from "get_malware"
![image](https://github.com/AlbertL7/The-PoorMans-Cyber-Threat-Feed/assets/71300144/bf532a9d-a696-4e30-8087-d970c2a921ca)


***


# ATP Hunter

## Future Updates to project

- Update script to check if country csv file already exists, if the csv file already exists, continue scraping but compare results to current csv file and append new results with not duplicates.
- I plan on writing a script to fetch the top 200 latest malware strains to put into a feedly filter
- I also plan on writng a script to scrape yara rules to be implemented into a SIEM

## Breif overview 
Harness the power of open-source intelligence by leveraging this script to automatically scrape and curate a list of cyber threat actors based on specified countries. Designed to tap into the vast data pool of malpedia.caad.fkie.fraunhofer.de, it retrieves a list of actors, their respective aliases, and constructs a custom filter URL for Feedly Pro+.

📌 Features:

Country-Specific Threat Intelligence: Input a two-letter country code and get a detailed threat feed tailored to that region.
User Agent Rotator: Avoid getting blocked by employing a range of user agents during your scraping sessions.
Threat Actor Aliases Finder: Enriches the feed with aliases of the threat actors, giving you more context and understanding about the threat landscape.
Feedly Pro+ Integration: Generates a custom Feedly filter URL to assist professionals in keeping abreast of the latest mentions of threat actors in news or articles.

🔧 Modules Used:

requests for handling web requests.
BeautifulSoup from bs4 for parsing HTML data.
colorama for terminal color outputs.
re for regular expressions.
pandas for data manipulation and CSV generation.
base64 for encoding the Feedly filter.

💡 Use Case:
Perfect for cybersecurity professionals, threat intelligence analysts, or anyone keen on gaining insights into the cyber threat landscape of specific countries without investing in costly threat feeds.

🔗 How To Use:

- Clone the repository.
- Ensure you have the required modules installed.
- Run the script.
- Enter the two-letter country code.
- Wait as it gathers the threat actors, their aliases, and constructs your Feedly Pro+ filter URL.
- Use the generated URL to keep an eye on mentions and activities related to the listed threat actors in feedly.
  
## Example, Pakistan Threat actors
![image](https://github.com/AlbertL7/The-PoorMans-Cyber-Threat-Feed/assets/71300144/96700923-2a5e-4a2b-a679-645f5a1c1207)

## Example, After entering generated URL for Feedly
![image](https://github.com/AlbertL7/The-PoorMans-Cyber-Threat-Feed/assets/71300144/3a9d3da2-4172-4d6f-aed2-1334f4abdc50)

## Example, Feed View
![image](https://github.com/AlbertL7/The-PoorMans-Cyber-Threat-Feed/assets/71300144/ba7ecbec-75b5-42a6-bee9-d0f635f8d5fa)

## Example, CSV file created
![image](https://github.com/AlbertL7/The-PoorMans-Cyber-Threat-Feed/assets/71300144/9f9042bc-c532-4e86-87d7-f80348bc68d1)
