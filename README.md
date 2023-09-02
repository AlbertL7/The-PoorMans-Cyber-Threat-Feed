# The PoorMans Cyber Threat Feed

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

## Example, Pakistan Threat actors
![image](https://github.com/AlbertL7/The-PoorMans-Cyber-Threat-Feed/assets/71300144/96700923-2a5e-4a2b-a679-645f5a1c1207)


💡 Use Case:
Perfect for cybersecurity professionals, threat intelligence analysts, or anyone keen on gaining insights into the cyber threat landscape of specific countries without investing in costly threat feeds.

🔗 How To Use:

- Clone the repository.
- Ensure you have the required modules installed.
- Run the script.
- Enter the two-letter country code.
- Wait as it gathers the threat actors, their aliases, and constructs your Feedly Pro+ filter URL.
- Use the generated URL to keep an eye on mentions and activities related to the listed threat actors in feedly.
