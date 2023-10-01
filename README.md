# The PoorMans Cyber Threat Feed

Harness the power of open-source intelligence by leveraging this script to automatically scrape and curate a list of cyber threat actors and the latest Malware. Designed to tap into the vast data pool of malpedia.caad.fkie.fraunhofer.de.

When integrated with Feedly, this tool aids in building a comprehensive threat intelligence database by collecting the latest Indicators of Compromise (IoCs), Tactics, Techniques, and Procedures (TTPs), and vulnerabilities from open-source intelligence performed by the latest threat acotors. This enables organizations and individuals to stay informed about emerging threats and enhance their security posture by proactively addressing potential vulnerabilities.

The intended use is to run these programs probably once a week to get a comprehensive overview of the latest threat actors and malware. This will enable you to update the Feedly filter as needed or perform VirusTotal retro hunts based on the yara rules found for the malware you are investigaing.  

# Malware Hunter

## Overview

The Malware Hunter app is a Python-based tool designed to gather and analyze information about malware from various sources. It integrates with Feedly to provide AI feeds in Pro+ and uses Malpedia for information retrieval. The tool is capable of querying malware data, displaying descriptions, and showing Yara rules for selected malware. It also provides options to create Feedly filters in both URL encoded and clear text formats. 

## Features

- Malware Querying: Allows users to query a specific amount of malware, displayed from newest to oldest.
- The search feature allows you to search for multiple different malware strains at the same time based on what you queried and grab the description and yara rules for each if used with --d or --y or both.
- Description Display: Provides detailed descriptions for the selected malware.
- Yara Rule Display: Shows Yara rules for selected malware.
- Feedly Filter Creation: Generates Feedly filters in URL encoded and clear text formats.
- Silent Mode: Suppresses default output.
- User-Agent Randomization: Uses different user agents for making requests to avoid blocking.
- Data Sorting: Sorts malware data based on the last updated date.
- User Interaction: Allows users to select malware interactively and decide whether to continue exploring other malware.

## Usage

usage: malware_hunter.py [-h] [--get_malware] [--search  [...]] [--ef] [--cf] [--d] [--y] [--us] [--s]

options:
  -h, --help        show this help message and exit
  --get_malware     Amount of Malware to Query, displayed from newest to oldest.
  --search  [ ...]  List of malware names to search for. Ex:"--search malware1 malware2 --d --y."
  --ef              Encoded Feedly Filter URL from queried malware
  --cf              Clear Text Feedly Filter from queried malware
  --d               Display the description for the selected malware
  --y               Display yara rule(s) for selected malware
  --us              Select From queried maalware, meant to be used with --search, --d and or --y
  --s               Silent mode, suppresses default output. Valid only when --ef, --cf, --d, or --y is used.

If you use the "--search" argument without the "--d" or "--y" argument you will not get any description or yara information but you will get the name, last updated, and family link.

## Example Commands
#### 1
```
python3 malware_hunter.py --get_malware 5 --ef --d
This command will query the 5 newest malwares, generate an encoded Feedly filter URL, and display a list of malware that is queried, depending on the malware you select a description will be displayed.
```
#### 2
```
python .\malware_hunter.py --us --d --y --search darkgate comebacker aria-body --ef --cf --get_malware 20 --s
This command will display the encoded feedly filter, clear text feedly filter, then query the malware you entered into the "--search" argument for the description and yara rule. Then enter into a user prompt asking if you would like to continue if "y" then a list of the output of the queried 20 values will be displayed. This will give you the option to select the corresponding number to display the yara rule or descrtion.
```
## Example Output of the second Example command
```
PS C:\Users\HOUSE-OF-L\Documents\Coding\VS Code\Web Scraping\Feedly_Filter_Create> python3 .\malware_hunter.py --us --d --y --search darkgate comebacker aria-body --ef --cf --get_malware 20 --s --o test.txt

*******************************
*  Encoded Feedly Filter URL  *
*******************************

https://feedly.com/i/powerSearch/in?options=eyJsYXllcnMiOlt7InBhcnRzIjpbeyJ0eXBlIjoiY3VzdG9tS2V5d29yZCIsInRleHQiOiI0aF9yYXQifSx7InRleHQiOiJBcmlhLWJvZHkifSx7InRleHQiOiJCcnV0ZSBSYXRlbCBDNCJ9LHsidGV4dCI6IkNvbWVCYWNrZXIifSx7InRleHQiOiJIaWphY2tMb2FkZXIifSx7InRleHQiOiJHcmFmdG9yIn0seyJ0ZXh0IjoiTHVhRHJlYW0ifSx7InRleHQiOiJSYWNrZXQgRG93bmxvYWRlciJ9LHsidGV4dCI6IkJCdG9rIn0seyJ0ZXh0IjoiRGFya0dhdGUifSx7InRleHQiOiJEQmF0TG9hZGVyIn0seyJ0ZXh0IjoiUGVucXVpbiBUdXJsYSJ9LHsidGV4dCI6IlFha0JvdCJ9LHsidGV4dCI6IjhCYXNlIn0seyJ0ZXh0IjoiQklTVFJPTUFUSCJ9LHsidGV4dCI6IkNlcmJlcnVzIn0seyJ0ZXh0IjoiRmF0YWxSYXQifSx7InRleHQiOiJQRUJCTEVEQVNIIn0seyJ0ZXh0IjoiUHVycGxlRm94In0seyJ0ZXh0IjoiVGlnZXIgUkFUIn1dLCJzYWxpZW5jZSI6Im1lbnRpb24iLCJzZWFyY2hIaW50IjoiIiwidHlwZSI6Im1hdGNoZXMifV0sImJ1bmRsZXMiOltdfQ==

*******************************
*  Clear Text Feedly Filter   *
*******************************

{"layers":[{"parts":[{"type":"customKeyword","text":"4h_rat"},{"text":"Aria-body"},{"text":"Brute Ratel C4"},{"text":"ComeBacker"},{"text":"HijackLoader"},{"text":"Graftor"},{"text":"LuaDream"},{"text":"Racket Downloader"},{"text":"BBtok"},{"text":"DarkGate"},{"text":"DBatLoader"},{"text":"Penquin Turla"},{"text":"QakBot"},{"text":"8Base"},{"text":"BISTROMATH"},{"text":"Cerberus"},{"text":"FatalRat"},{"text":"PEBBLEDASH"},{"text":"PurpleFox"},{"text":"Tiger RAT"}],"salience":"mention","searchHint":"","type":"matches"}],"bundles":[]}

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@       Search Results        @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@


*******************************
*     Searching darkgate       *
*******************************

[+] Searching for darkgate:
Found: DarkGate ---> Last Updated: 2023-09-25 ---> Family Link: https://malpedia.caad.fkie.fraunhofer.de/details/win.darkgate

*******************************
*         Description         *
*******************************

 First documented in 2018, DarkGate is a commodity loader with features that include the ability to download and execute files to memory, a Hidden Virtual Network Computing (HVNC) module, keylogging, information-stealing capabilities, and privilege escalation. 
DarkGate makes use of legitimate AutoIt files and typically runs multiple AutoIt scripts. New versions of DarkGate have been advertised on a Russian language eCrime forum since May 2023. First documented in 2018, DarkGate is a commodity loader with features that include the ability to download and execute files to memory, a Hidden Virtual Network Computing (HVNC) module, keylogging, information-stealing capabilities, and privilege escalation. DarkGate makes use of legitimate AutoIt files and typically runs multiple AutoIt scripts. New versions of DarkGate have been advertised on a Russian language eCrime forum since May 2023. There is no Yara-Signature yet.


*******************************
*   No Yara rule Available    *
*******************************


*******************************
*     Searching comebacker       *
*******************************

[+] Searching for comebacker:
Found: ComeBacker ---> Last Updated: 2023-09-29 ---> Family Link: https://malpedia.caad.fkie.fraunhofer.de/details/win.comebacker

*******************************
*         Description         *
*******************************

 ComeBacker was found in a backdoored Visual Studio project that was used to target security researchers in Q4 2020 and early 2021.It is an HTTP(S) downloader.It uses the AES CBC cipher implemented through the OpenSSL's EVP interface for decryption of its configuration, and also for encryption and decryption of the client-server communication. The parameter names in HTTP POST requests of the client are generated randomly. As the initial connection, the client exchanges the keys with the server via the Diffie–Hellman 
key agreement protocol for the elliptic curve secp521r1. The client generates a random 32-bytes long private key, and the server responds with its public key in a buffer starting with the wide character "0".Next, the clients sends the current local time, and the server responds with a buffer containing multiple values separated with the pipe symbol. The typical values are the encrypted payload, the export to execute, and the MD5 hash of the decrypted DLL to verify the authenticity of the payload. There are variants of ComeBacker without statically linked OpenSSL. In that case, the key exchange is omitted and AES CBC is replaced with HC-256. ComeBacker was found in a backdoored Visual Studio project that was used to target security researchers in Q4 2020 and early 2021. It 
is an HTTP(S) downloader. It uses the AES CBC cipher implemented through the OpenSSL's EVP interface for decryption of its configuration, and also for encryption and decryption of the client-server communication. The parameter names in HTTP POST requests of the client are generated randomly. As the initial connection, the client exchanges the keys with the server via the Diffie–Hellman key agreement protocol for the elliptic curve secp521r1. The client generates a random 32-bytes long private key, and the server responds with its public key in a buffer starting with the wide character "0". Next, the clients sends the current local time, and the server responds with a buffer containing multiple values separated with the pipe symbol. The typical values are the encrypted payload, the export to execute, and the MD5 hash of the decrypted DLL to verify the authenticity of the payload. There are variants of ComeBacker without statically linked OpenSSL. In that case, the key exchange is omitted and AES CBC is replaced with HC-256. There is no Yara-Signature yet.


*******************************
*   No Yara rule Available    *
*******************************


*******************************
*     Searching aria-body       *
*******************************

[+] Searching for aria-body:
Found: Aria-body ---> Last Updated: 2023-09-29 ---> Family Link: https://malpedia.caad.fkie.fraunhofer.de/details/win.ariabody

*******************************
*         Description         *
*******************************

 There is no description at this point.


*******************************
*          Yara rule          *
*******************************

rule win_ariabody_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-07-11"
        version = "1"
        description = "Detects win.ariabody."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ariabody"
        malpedia_rule_date = "20230705"
        malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
        malpedia_version = "20230715"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 50 ff5204 8b1e 8bd0 }
            // n = 4, score = 300
            //   50                   | push                eax
            //   ff5204               | call                dword ptr [edx + 4]
            //   8b1e                 | mov                 ebx, dword ptr [esi]
            //   8bd0                 | mov                 edx, eax

        $sequence_1 = { 8bcf 0fb6c0 50 ff75fc e8???????? 83c40c 85db }
            // n = 7, score = 300
            //   8bcf                 | mov                 ecx, edi
            //   0fb6c0               | movzx               eax, al
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |
            //   83c40c               | add                 esp, 0xc
            //   85db                 | test                ebx, ebx

        $sequence_2 = { 2bd1 8a01 84c0 7406 }
            // n = 4, score = 300
            //   2bd1                 | sub                 edx, ecx
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   84c0                 | test                al, al
            //   7406                 | je                  8

        $sequence_3 = { 8bf2 56 8d55fc 03f9 e8???????? 59 85c0 }
            // n = 7, score = 300
            //   8bf2                 | mov                 esi, edx
            //   56                   | push                esi
            //   8d55fc               | lea                 edx, [ebp - 4]
            //   03f9                 | add                 edi, ecx
            //   e8????????           |
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax

        $sequence_4 = { 8bf8 893e eb13 8b16 8bcf e8???????? 8906 }
            // n = 7, score = 300
            //   8bf8                 | mov                 edi, eax
            //   893e                 | mov                 dword ptr [esi], edi
            //   eb13                 | jmp                 0x15
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |
            //   8906                 | mov                 dword ptr [esi], eax

        $sequence_5 = { 7406 3ac3 7402 32c3 }
            // n = 4, score = 300
            //   7406                 | je                  8
            //   3ac3                 | cmp                 al, bl
            //   7402                 | je                  4
            //   32c3                 | xor                 al, bl

        $sequence_6 = { 55 8bec 83ec50 53 57 8bd9 e8???????? }
            // n = 7, score = 300
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec50               | sub                 esp, 0x50
            //   53                   | push                ebx
            //   57                   | push                edi
            //   8bd9                 | mov                 ebx, ecx
            //   e8????????           |

        $sequence_7 = { 8d0c30 ffd1 8bc6 5f 5e }
            // n = 5, score = 300
            //   8d0c30               | lea                 ecx, [eax + esi]
            //   ffd1                 | call                ecx
            //   8bc6                 | mov                 eax, esi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_8 = { 48630b 4c8d2dd59f0000 488bc1 83e11f 41b801000000 48c1f805 450ae0 }
            // n = 7, score = 100
            //   48630b               | mov                 word ptr [ecx + 0x164], ax
            //   4c8d2dd59f0000       | mov                 word ptr [ecx + 0x26a], ax
            //   488bc1               | dec                 eax
            //   83e11f               | lea                 eax, [0xfeeb]
            //   41b801000000         | dec                 eax
            //   48c1f805             | mov                 dword ptr [ecx + 0xb8], eax
            //   450ae0               | dec                 eax

        $sequence_9 = { 88443109 8a45d9 4b8b8cea808a0100 88443139 4b8b84ea808a0100 8854303a eb4c }
            // n = 7, score = 100
            //   88443109             | dec                 eax
            //   8a45d9               | lea                 edx, [0xe9e5]
            //   4b8b8cea808a0100     | inc                 esi
            //   88443139             | dec                 eax
            //   4b8b84ea808a0100     | lea                 ecx, [eax + eax*4]
            //   8854303a             | dec                 eax
            //   eb4c                 | lea                 ecx, [edx + ecx*8]

        $sequence_10 = { eb97 488d15997b0000 488d0d727b0000 e8???????? 488d15967b0000 }
            // n = 5, score = 100
            //   eb97                 | mov                 byte ptr [ecx + esi + 9], al
            //   488d15997b0000       | mov                 al, byte ptr [ebp - 0x27]
            //   488d0d727b0000       | dec                 ebx
            //   e8????????           |
            //   488d15967b0000       | mov                 ecx, dword ptr [edx + ebp*8 + 0x18a80]

        $sequence_11 = { 488d0db4db0000 488bc2 83e21f 48c1f805 }
            // n = 4, score = 100
            //   488d0db4db0000       | dec                 eax
            //   488bc2               | lea                 ecx, [0xdbb4]
            //   83e21f               | dec                 eax
            //   48c1f805             | mov                 eax, edx

        $sequence_12 = { 48c7402000000000 41ff96d0000000 85c0 0f84a6000000 4533c0 4c89e1 4533c9 }
            // n = 7, score = 100
            //   48c7402000000000     | dec                 eax
            //   41ff96d0000000       | lea                 edx, [0x7b99]
            //   85c0                 | dec                 eax
            //   0f84a6000000         | lea                 ecx, [0x7b72]
            //   4533c0               | dec                 eax
            //   4c89e1               | lea                 edx, [0x7b96]
            //   4533c9               | mov                 eax, 0x43

        $sequence_13 = { 48c7c102000080 488d942434010000 4533c0 41b906000200 c702534f4654 }
            // n = 5, score = 100
            //   48c7c102000080       | and                 dword ptr [ecx + 0x470], 0
            //   488d942434010000     | dec                 eax
            //   4533c0               | mov                 dword ptr [eax + 0x20], 0
            //   41b906000200         | inc                 ecx
            //   c702534f4654         | call                dword ptr [esi + 0xd0]

        $sequence_14 = { 4863c6 488d15e5e90000 ffc6 488d0c80 488d0cca }
            // n = 5, score = 100
            //   4863c6               | and                 edx, 0x1f
            //   488d15e5e90000       | dec                 eax
            //   ffc6                 | sar                 eax, 5
            //   488d0c80             | dec                 eax
            //   488d0cca             | arpl                si, ax

        $sequence_15 = { b843000000 66898164010000 6689816a020000 488d05ebfe0000 488981b8000000 4883a17004000000 }
            // n = 6, score = 100
            //   b843000000           | mov                 byte ptr [ecx + esi + 0x39], al
            //   66898164010000       | dec                 ebx
            //   6689816a020000       | mov                 eax, dword ptr [edx + ebp*8 + 0x18a80]
            //   488d05ebfe0000       | mov                 byte ptr [eax + esi + 0x3a], dl
            //   488981b8000000       | jmp                 0x5e
            //   4883a17004000000     | jmp                 0xffffff99

    condition:
        7 of them and filesize < 253952
}


*******************************
*       Select Malware        *
*******************************

1. Malware: 4h_rat
2. Malware: Aria-body
3. Malware: Brute Ratel C4
4. Malware: ComeBacker
5. Malware: HijackLoader
6. Malware: Graftor
7. Malware: LuaDream
8. Malware: Racket Downloader
9. Malware: BBtok
10. Malware: DarkGate
11. Malware: DBatLoader
13. Malware: QakBot
14. Malware: 8Base
15. Malware: BISTROMATH
16. Malware: Cerberus
17. Malware: FatalRat
18. Malware: PEBBLEDASH
19. Malware: PurpleFox
20. Malware: Tiger RAT

[+] Enter the number corresponding to the malware you want to explore:
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
