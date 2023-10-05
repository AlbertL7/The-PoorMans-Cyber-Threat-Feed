# TLD's in the Domains key was pulled from https://data.iana.org/TLD/tlds-alpha-by-domain.txt

import re
import tkinter as tk
import tkinter.filedialog
import tkinter.simpledialog
import tkinter.messagebox
import os
from tkinter import scrolledtext

regexes = { #catch IPv4 without defang
    'IPv4': re.compile(r'(?:\d{1,3}\[\.\]|\d{1,3}\.)(?:\d{1,3}\[\.\]|\d{1,3}\.)(?:\d{1,3}\[\.\]|\d{1,3}\.)\d{1,3}|(?:\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)'), #catch all defanged IPv4
    'Domains': re.compile(r"(?<![@a-zA-Z0-9._%+-])([a-zA-Z0-9\-]+\.(?:com|org|top|ga|ml|info|cf|gq|icu|wang|live|cn|online|host|us|tk|fyi|buzz|net|io|gov|edu|eu|uk|de|fr|me|es|bid|shop|it|nl|ru|jp|in|br|au|ca|mx|nz|tv|cc|co|ro|us|asia|mobi|pro|tel|aero|travel|xyz|dagree|club|online|site|store|app|blog|design|tech|guru|ninja|news|media|network|agency|digital|email|link|click|world|today|solutions|tools|company|photography|tips|technology|works|zone|watch|video|guide|rodeo|life|chat|expert|haus|marketing|center|systems|academy|training|services|support|education|church|community|foundation|charity|ngo|ong|social|events|productions|fun|games|reviews|business|gdn|enterprises|international|land|properties|rentals|ventures|holdings|luxury|boutique|accountants|agency|associates|attorney|cc|construction|contractors|credit|dentist|engineer|equipment|estate|financial|florist|gallery|graphics|law|lawyer|management|marketing|media|photography|photos|productions|properties|realtor|realty|solutions|studio|systems|technology|ventures|vet|veterinarian|AAA|AARP|ABB|ABBOTT|ABBVIE|ABC|ABLE|ABOGADO|ABUDHABI|AC|ACADEMY|ACCENTURE|ACCOUNTANT|ACCOUNTANTS|ACO|ACTOR|AD|ADS|ADULT|AE|AEG|AERO|AETNA|AF|AFL|AFRICA|AG|AGAKHAN|AGENCY|AI|AIG|AIRBUS|AIRFORCE|AIRTEL|AKDN|AL|ALIBABA|ALIPAY|ALLFINANZ|ALLSTATE|ALLY|ALSACE|ALSTOM|AM|AMAZON|AMERICANEXPRESS|AMERICANFAMILY|AMEX|AMFAM|AMICA|AMSTERDAM|ANALYTICS|ANDROID|ANQUAN|ANZ|AO|AOL|APARTMENTS|APP|APPLE|AQ|AQUARELLE|AR|ARAB|ARAMCO|ARCHI|ARMY|ARPA|ART|ARTE|AS|ASDA|ASIA|ASSOCIATES|AT|ATHLETA|ATTORNEY|AU|AUCTION|AUDI|AUDIBLE|AUDIO|AUSPOST|AUTHOR|AUTO|AUTOS|AVIANCA|AW|AWS|AX|AXA|AZ|AZURE|BA|BABY|BAIDU|BANAMEX|BANANAREPUBLIC|BAND|BANK|BAR|BARCELONA|BARCLAYCARD|BARCLAYS|BAREFOOT|BARGAINS|BASEBALL|BASKETBALL|BAUHAUS|BAYERN|BB|BBC|BBT|BBVA|BCG|BCN|BD|BE|BEATS|BEAUTY|BEER|BENTLEY|BERLIN|BEST|BESTBUY|BET|BF|BG|BH|BHARTI|BI|BIBLE|BID|BIKE|BING|BINGO|BIO|BIZ|BJ|BLACK|BLACKFRIDAY|BLOCKBUSTER|BLOG|BLOOMBERG|BLUE|BM|BMS|BMW|BN|BNPPARIBAS|BO|BOATS|BOEHRINGER|BOFA|BOM|BOND|BOO|BOOK|BOOKING|BOSCH|BOSTIK|BOSTON|BOT|BOUTIQUE|BOX|BR|BRADESCO|BRIDGESTONE|BROADWAY|BROKER|BROTHER|BRUSSELS|BS|BT|BUILD|BUILDERS|BUSINESS|BUY|BUZZ|BV|BW|BY|BZ|BZH|CA|CAB|CAFE|CAL|CALL|CALVINKLEIN|CAM|CAMERA|CAMP|CANON|CAPETOWN|CAPITAL|CAPITALONE|CAR|CARAVAN|CARDS|CARE|CAREER|CAREERS|CARS|CASA|CASE|CASH|CASINO|CAT|CATERING|CATHOLIC|CBA|CBN|CBRE|CBS|CC|CD|CENTER|CEO|CERN|CF|CFA|CFD|CG|CH|CHANEL|CHANNEL|CHARITY|CHASE|CHAT|CHEAP|CHINTAI|CHRISTMAS|CHROME|CHURCH|CI|CIPRIANI|CIRCLE|CISCO|CITADEL|CITI|CITIC|CITY|CITYEATS|CK|CL|CLAIMS|CLEANING|CLICK|CLINIC|CLINIQUE|CLOTHING|CLOUD|CLUB|CLUBMED|CM|CN|CO|COACH|CODES|COFFEE|COLLEGE|COLOGNE|COM|COMCAST|COMMBANK|COMMUNITY|COMPANY|COMPARE|COMPUTER|COMSEC|CONDOS|CONSTRUCTION|CONSULTING|CONTACT|CONTRACTORS|COOKING|COOL|COOP|CORSICA|COUNTRY|COUPON|COUPONS|COURSES|CPA|CR|CREDIT|CREDITCARD|CREDITUNION|CRICKET|CROWN|CRS|CRUISE|CRUISES|CU|CUISINELLA|CV|CW|CX|CY|CYMRU|CYOU|CZ|DABUR|DAD|DANCE|DATA|DATE|DATING|DATSUN|DAY|DCLK|DDS|DE|DEAL|DEALER|DEALS|DEGREE|DELIVERY|DELL|DELOITTE|DELTA|DEMOCRAT|DENTAL|DENTIST|DESI|DESIGN|DEV|DHL|DIAMONDS|DIET|DIGITAL|DIRECT|DIRECTORY|DISCOUNT|DISCOVER|DISH|DIY|DJ|DK|DM|DNP|DO|DOCS|DOCTOR|DOG|DOMAINS|DOT|DOWNLOAD|DRIVE|DTV|DUBAI|DUNLOP|DUPONT|DURBAN|DVAG|DVR|DZ|EARTH|EAT|EC|ECO|EDEKA|EDU|EDUCATION|EE|EG|EMAIL|EMERCK|ENERGY|ENGINEER|ENGINEERING|ENTERPRISES|EPSON|EQUIPMENT|ER|ERICSSON|ERNI|ES|ESQ|ESTATE|ET|ETISALAT|EU|EUROVISION|EUS|EVENTS|EXCHANGE|EXPERT|EXPOSED|EXPRESS|EXTRASPACE|FAGE|FAIL|FAIRWINDS|FAITH|FAMILY|FAN|FANS|FARM|FARMERS|FASHION|FAST|FEDEX|FEEDBACK|FERRARI|FERRERO|FI|FIDELITY|FIDO|FILM|FINAL|FINANCE|FINANCIAL|FIRE|FIRESTONE|FIRMDALE|FISH|FISHING|FIT|FITNESS|FJ|FK|FLICKR|FLIGHTS|FLIR|FLORIST|FLOWERS|FLY|FM|FO|FOO|FOOD|FOOTBALL|FORD|FOREX|FORSALE|FORUM|FOUNDATION|FOX|FR|FREE|FRESENIUS|FRL|FROGANS|FRONTDOOR|FRONTIER|FTR|FUJITSU|FUN|FUND|FURNITURE|FUTBOL|FYI|GA|GAL|GALLERY|GALLO|GALLUP|GAME|GAMES|GAP|GARDEN|GAY|GB|GBIZ|GD|GDN|GE|GEA|GENT|GENTING|GEORGE|GF|GG|GGEE|GH|GI|GIFT|GIFTS|GIVES|GIVING|GL|GLASS|GLE|GLOBAL|GLOBO|GM|GMAIL|GMBH|GMO|GMX|GN|GODADDY|GOLD|GOLDPOINT|GOLF|GOO|GOODYEAR|GOOG|GOOGLE|GOP|GOT|GOV|GP|GQ|GR|GRAINGER|GRAPHICS|GRATIS|GREEN|GRIPE|GROCERY|GROUP|GS|GT|GU|GUARDIAN|GUCCI|GUGE|GUIDE|GUITARS|GURU|GW|GY|HAIR|HAMBURG|HANGOUT|HAUS|HBO|HDFC|HDFCBANK|HEALTH|HEALTHCARE|HELP|HELSINKI|HERE|HERMES|HIPHOP|HISAMITSU|HITACHI|HIV|HK|HKT|HM|HN|HOCKEY|HOLDINGS|HOLIDAY|HOMEDEPOT|HOMEGOODS|HOMES|HOMESENSE|HONDA|HORSE|HOSPITAL|HOST|HOSTING|HOT|HOTELS|HOTMAIL|HOUSE|HOW|HR|HSBC|HT|HU|HUGHES|HYATT|HYUNDAI|IBM|ICBC|ICE|ICU|ID|IE|IEEE|IFM|IKANO|IL|IM|IMAMAT|IMDB|IMMO|IMMOBILIEN|IN|INC|INDUSTRIES|INFINITI|INFO|ING|INK|INSTITUTE|INSURANCE|INSURE|INT|INTERNATIONAL|INTUIT|INVESTMENTS|IO|IPIRANGA|IQ|IR|IRISH|IS|ISMAILI|IST|ISTANBUL|IT|ITAU|ITV|JAGUAR|JAVA|JCB|JE|JEEP|JETZT|JEWELRY|JIO|JLL|JM|JMP|JNJ|JO|JOBS|JOBURG|JOT|JOY|JP|JPMORGAN|JPRS|JUEGOS|JUNIPER|KAUFEN|KDDI|KE|KERRYHOTELS|KERRYLOGISTICS|KERRYPROPERTIES|KFH|KG|KH|KI|KIA|KIDS|KIM|KINDER|KINDLE|KITCHEN|KIWI|KM|KN|KOELN|KOMATSU|KOSHER|KP|KPMG|KPN|KR|KRD|KRED|KUOKGROUP|KW|KY|KYOTO|KZ|LA|LACAIXA|LAMBORGHINI|LAMER|LANCASTER|LAND|LANDROVER|LANXESS|LASALLE|LAT|LATINO|LATROBE|LAW|LAWYER|LB|LC|LDS|LEASE|LECLERC|LEFRAK|LEGAL|LEGO|LEXUS|LGBT|LI|LIDL|LIFE|LIFEINSURANCE|LIFESTYLE|LIGHTING|LIKE|LILLY|LIMITED|LIMO|LINCOLN|LINK|LIPSY|LIVE|LIVING|LK|LLC|LLP|LOAN|LOANS|LOCKER|LOCUS|LOL|LONDON|LOTTE|LOTTO|LOVE|LPL|LPLFINANCIAL|LR|LS|LT|LTD|LTDA|LU|LUNDBECK|LUXE|LUXURY|LV|LY|MA|MADRID|MAIF|MAISON|MAKEUP|MAN|MANAGEMENT|MANGO|MAP|MARKET|MARKETING|MARKETS|MARRIOTT|MARSHALLS|MATTEL|MBA|MC|MCKINSEY|MD|ME|MED|MEDIA|MEET|MELBOURNE|MEME|MEMORIAL|MEN|MENU|MERCKMSD|MG|MH|MIAMI|MICROSOFT|MIL|MINI|MINT|MIT|MITSUBISHI|MK|ML|MLB|MLS|MM|MMA|MN|MO|MOBI|MOBILE|MODA|MOE|MOI|MOM|MONASH|MONEY|MONSTER|MORMON|MORTGAGE|MOSCOW|MOTO|MOTORCYCLES|MOV|MOVIE|MP|MQ|MR|MS|MSD|MT|MTN|MTR|MU|MUSEUM|MUSIC|MV|MW|MX|MY|MZ|NA|NAB|NAGOYA|NAME|NATURA|NAVY|NBA|NC|NE|NEC|NET|NETBANK|NETFLIX|NETWORK|NEUSTAR|NEW|NEWS|NEXT|NEXTDIRECT|NEXUS|NF|NFL|NG|NGO|NHK|NI|NICO|NIKE|NIKON|NINJA|NISSAN|NISSAY|NL|NO|NOKIA|NORTON|NOW|NOWRUZ|NOWTV|NP|NR|NRA|NRW|NTT|NU|NYC|NZ|OBI|OBSERVER|OFFICE|OKINAWA|OLAYAN|OLAYANGROUP|OLDNAVY|OLLO|OM|OMEGA|ONE|ONG|ONL|ONLINE|OOO|OPEN|ORACLE|ORANGE|ORG|ORGANIC|ORIGINS|OSAKA|OTSUKA|OTT|OVH|PA|PAGE|PANASONIC|PARIS|PARS|PARTNERS|PARTS|PARTY|PAY|PCCW|PE|PET|PF|PFIZER|PG|PH|PHARMACY|PHD|PHILIPS|PHONE|PHOTO|PHOTOGRAPHY|PHOTOS|PHYSIO|PICS|PICTET|PICTURES|PID|PIN|PING|PINK|PIONEER|PIZZA|PK|PL|PLACE|PLAY|PLAYSTATION|PLUMBING|PLUS|PM|PN|PNC|POHL|POKER|POLITIE|PORN|POST|PR|PRAMERICA|PRAXI|PRESS|PRIME|PRO|PROD|PRODUCTIONS|PROF|PROGRESSIVE|PROMO|PROPERTIES|PROPERTY|PROTECTION|PRU|PRUDENTIAL|PS|PT|PUB|PW|PWC|PY|QA|QPON|QUEBEC|QUEST|RACING|RADIO|RE|READ|REALESTATE|REALTOR|REALTY|RECIPES|RED|REDSTONE|REDUMBRELLA|REHAB|REISE|REISEN|REIT|RELIANCE|REN|RENT|RENTALS|REPAIR|REPORT|REPUBLICAN|REST|RESTAURANT|REVIEW|REVIEWS|REXROTH|RICH|RICHARDLI|RICOH|RIL|RIO|RIP|RO|ROCHER|ROCKS|RODEO|ROGERS|ROOM|RS|RSVP|RU|RUGBY|RUHR|RUN|RW|RWE|RYUKYU|SA|SAARLAND|SAFE|SAFETY|SAKURA|SALE|SALON|SAMSCLUB|SAMSUNG|SANDVIK|SANDVIKCOROMANT|SANOFI|SAP|SARL|SAS|SAVE|SAXO|SB|SBI|SBS|SC|SCA|SCB|SCHAEFFLER|SCHMIDT|SCHOLARSHIPS|SCHOOL|SCHULE|SCHWARZ|SCIENCE|SCOT|SD|SE|SEARCH|SEAT|SECURE|SECURITY|SEEK|SELECT|SENER|SERVICES|SEVEN|SEW|SEX|SEXY|SFR|SG|SH|SHANGRILA|SHARP|SHAW|SHELL|SHIA|SHIKSHA|SHOES|SHOP|SHOPPING|SHOUJI|SHOW|SHOWTIME|SI|SILK|SINA|SINGLES|SITE|SJ|SK|SKI|SKIN|SKY|SKYPE|SL|SLING|SM|SMART|SMILE|SN|SNCF|SO|SOCCER|SOCIAL|SOFTBANK|SOFTWARE|SOHU|SOLAR|SOLUTIONS|SONG|SONY|SOY|SPA|SPACE|SPORT|SPOT|SR|SRL|SS|ST|STADA|STAPLES|STAR|STATEBANK|STATEFARM|STC|STCGROUP|STOCKHOLM|STORAGE|STORE|STREAM|STUDIO|STUDY|STYLE|SU|SUCKS|SUPPLIES|SUPPLY|SUPPORT|SURF|SURGERY|SUZUKI|SV|SWATCH|SWISS|SX|SY|SYDNEY|SYSTEMS|SZ|TAB|TAIPEI|TALK|TAOBAO|TARGET|TATAMOTORS|TATAR|TATTOO|TAX|TAXI|TC|TCI|TD|TDK|TEAM|TECH|TECHNOLOGY|TEL|TEMASEK|TENNIS|TEVA|TF|TG|TH|THD|THEATER|THEATRE|TIAA|TICKETS|TIENDA|TIPS|TIRES|TIROL|TJ|TJMAXX|TJX|TK|TKMAXX|TL|TM|TMALL|TN|TO|TODAY|TOKYO|TOOLS|TOP|TORAY|TOSHIBA|TOTAL|TOURS|TOWN|TOYOTA|TOYS|TR|TRADE|TRADING|TRAINING|TRAVEL|TRAVELERS|TRAVELERSINSURANCE|TRUST|TRV|TT|TUBE|TUI|TUNES|TUSHU|TV|TVS|TW|TZ|UA|UBANK|UBS|UG|UK|UNICOM|UNIVERSITY|UNO|UOL|UPS|US|UY|UZ|VA|VACATIONS|VANA|VANGUARD|VC|VE|VEGAS|VENTURES|VERISIGN|VERSICHERUNG|VET|VG|VI|VIAJES|VIDEO|VIG|VIKING|VILLAS|VIN|VIP|VIRGIN|VISA|VISION|VIVA|VIVO|VLAANDEREN|VN|VODKA|VOLKSWAGEN|VOLVO|VOTE|VOTING|VOTO|VOYAGE|VU|WALES|WALMART|WALTER|WANG|WANGGOU|WATCH|WATCHES|WEATHER|WEATHERCHANNEL|WEBCAM|WEBER|WEBSITE|WED|WEDDING|WEIBO|WEIR|WF|WHOSWHO|WIEN|WIKI|WILLIAMHILL|WIN|WINDOWS|WINE|WINNERS|WME|WOLTERSKLUWER|WOODSIDE|WORK|WORKS|WORLD|WOW|WS|WTC|WTF|XBOX|XEROX|XFINITY|XIHUAN|XIN|XN--11B4C3D|XN--1CK2E1B|XN--1QQW23A|XN--2SCRJ9C|XN--30RR7Y|XN--3BST00M|XN--3DS443G|XN--3E0B707E|XN--3HCRJ9C|XN--3PXU8K|XN--42C2D9A|XN--45BR5CYL|XN--45BRJ9C|XN--45Q11C|XN--4DBRK0CE|XN--4GBRIM|XN--54B7FTA0CC|XN--55QW42G|XN--55QX5D|XN--5SU34J936BGSG|XN--5TZM5G|XN--6FRZ82G|XN--6QQ986B3XL|XN--80ADXHKS|XN--80AO21A|XN--80AQECDR1A|XN--80ASEHDB|XN--80ASWG|XN--8Y0A063A|XN--90A3AC|XN--90AE|XN--90AIS|XN--9DBQ2A|XN--9ET52U|XN--9KRT00A|XN--B4W605FERD|XN--BCK1B9A5DRE4C|XN--C1AVG|XN--C2BR7G|XN--CCK2B3B|XN--CCKWCXETD|XN--CG4BKI|XN--CLCHC0EA0B2G2A9GCD|XN--CZR694B|XN--CZRS0T|XN--CZRU2D|XN--D1ACJ3B|XN--D1ALF|XN--E1A4C|XN--ECKVDTC9D|XN--EFVY88H|XN--FCT429K|XN--FHBEI|XN--FIQ228C5HS|XN--FIQ64B|XN--FIQS8S|XN--FIQZ9S|XN--FJQ720A|XN--FLW351E|XN--FPCRJ9C3D|XN--FZC2C9E2C|XN--FZYS8D69UVGM|XN--G2XX48C|XN--GCKR3F0F|XN--GECRJ9C|XN--GK3AT1E|XN--H2BREG3EVE|XN--H2BRJ9C|XN--H2BRJ9C8C|XN--HXT814E|XN--I1B6B1A6A2E|XN--IMR513N|XN--IO0A7I|XN--J1AEF|XN--J1AMH|XN--J6W193G|XN--JLQ480N2RG|XN--JVR189M|XN--KCRX77D1X4A|XN--KPRW13D|XN--KPRY57D|XN--KPUT3I|XN--L1ACC|XN--LGBBAT1AD8J|XN--MGB9AWBF|XN--MGBA3A3EJT|XN--MGBA3A4F16A|XN--MGBA7C0BBN0A|XN--MGBAAKC7DVF|XN--MGBAAM7A8H|XN--MGBAB2BD|XN--MGBAH1A3HJKRD|XN--MGBAI9AZGQP6J|XN--MGBAYH7GPA|XN--MGBBH1A|XN--MGBBH1A71E|XN--MGBC0A9AZCG|XN--MGBCA7DZDO|XN--MGBCPQ6GPA1A|XN--MGBERP4A5D4AR|XN--MGBGU82A|XN--MGBI4ECEXP|XN--MGBPL2FH|XN--MGBT3DHD|XN--MGBTX2B|XN--MGBX4CD0AB|XN--MIX891F|XN--MK1BU44C|XN--MXTQ1M|XN--NGBC5AZD|XN--NGBE9E0A|XN--NGBRX|XN--NODE|XN--NQV7F|XN--NQV7FS00EMA|XN--NYQY26A|XN--O3CW4H|XN--OGBPF8FL|XN--OTU796D|XN--P1ACF|XN--P1AI|XN--PGBS0DH|XN--PSSY2U|XN--Q7CE6A|XN--Q9JYB4C|XN--QCKA1PMC|XN--QXA6A|XN--QXAM|XN--RHQV96G|XN--ROVU88B|XN--RVC1E0AM3E|XN--S9BRJ9C|XN--SES554G|XN--T60B56A|XN--TCKWE|XN--TIQ49XQYJ|XN--UNUP4Y|XN--VERMGENSBERATER-CTB|XN--VERMGENSBERATUNG-PWB|XN--VHQUV|XN--VUQ861B|XN--W4R85EL8FHU5DNRA|XN--W4RS40L|XN--WGBH1C|XN--WGBL6A|XN--XHQ521B|XN--XKC2AL3HYE2A|XN--XKC2DL3A5EE0H|XN--Y9A3AQ|XN--YFRO4I67O|XN--YGBI2AMMX|XN--ZFR164B|XXX|XYZ|YACHTS|YAHOO|YAMAXUN|YANDEX|YE|YODOBASHI|YOGA|YOKOHAMA|YOU|YOUTUBE|YT|YUN|ZA|ZAPPOS|ZARA|ZERO|ZIP|ZM|ZONE|ZUERICH|ZW))\b"),
    'Sub Domains': re.compile(r'(?<![@a-zA-Z0-9._%+-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}'),
    'URLs': re.compile(r'(?i)(hxxps?:\/\/(?:\[[^\]]+\]|\w+|\[\.\])+(?:\.\w+|\[\.\]\w+|\-\w+)*(?:\/[^\s]*)?)|((?:hxxps?://)?(?:[a-zA-Z0-9-]+\[\.\])+[a-zA-Z]+(?:/[^\s]*)?)|(https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)'), #catch all URL's
    'IP URL': re.compile(r'hxxps?:\/\/(?:\d{1,3}\.|\[\.\])?(?:\d{1,3}\.|\[\.\])?(?:\d{1,3}\.|\[\.\])?\d{1,3}(?:\[\.\]\d{1,3})?\/\d+\/[a-f0-9]+'), #catch all defanged ip addresses present in URL's
    'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'), # catch all md5 hashes
    'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'), # catch all sha1 hashes
    'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'), #catch all sha256 hashes
    'CVEs': re.compile(r'(?:CVE-\d{4}-\d{4,}|CVE[\s\[\(]\d{4}-\d{4,}[\]\)])'),
    'File Extensions': re.compile(r"""[^'\" \t\n\r\f\v/\\]*\.(doc|docx|pdf|ppt|pptx|txt|rtf|xls|xlsx|odt|jpeg|jpg|png|me|info|biz|gif|bmp|svg|tiff|psd|ico|mp3|wav|aac|flac|ogg|m4a|wma|mp4|avi|mkv|flv|mov|wmv|mpeg|zip|rar|7z|tar|gz|bz2|iso|html|htm|css|js|php|py|java|cpp|c|h|cs|sql|db|mdb|xml|json|exe|dll|sys|ini|bat|vbs|dwg|dxf|3ds|max|skp|proj|aep|prproj|veg|cad|stl|step|dat|csv|log|mat|nc|vmdk|vdi|img|qcow2|ttf|otf|fon|bak|tmp|dmp|epub|mobi|azw|azw3|git|svn|sh|bash|ps1|cmd|cfg|conf|yml|yaml|sass|scss|less|jsx|ts|tsx|npm|gem|pip|jar|deb|rpm|swf|lisp|go|rb|r|vmx|ova|ovf|vhdx|hdd|mid|midi|als|ftm|rex|unity|blend|unr|pak|bsp|pem|crt|csr|key|pgp|apk|ipa|app|aab|xapk|md|markdown|tex|bib|cls|vrml|x3d|u3d|ar|sbsar|ovpn|pcf|cisco|rdp|ssh|spss|sav|rdata|dta|do|ftl|twig|jinja|tpl|edml|obj|mtl|dae|abc|c4d|fbx|vrm|glb|gltf|usdz|reg|pol|inf|msi|msp|awk|sed|groovy|lua|tcl|gitignore|gitattributes|hgignore|dockerfile|dockerignore|sqlite|dbf|accdb|ora|frm|chm|mht|epub|mobi|lit|ai|eps|indd|xd|fig|rbw|pl|swift|kt|scala|ics|vcs|ical|zsh|fish)(?=\W|$)"""),
    'Emails': re.compile(r'\b([a-z][_a-z0-9-.]+@[a-z0-9-]+\.[a-z]+)\b'),
    'Registry': re.compile(r'\b((HKLM|HKCU)\\[\\A-Za-z0-9-_]+)\b'),
}

class IOCExtractor(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IOC Extractor")
        self.geometry("1600x800")  # Adjusted the geometry to accommodate the new widget
        self.article_input = scrolledtext.ScrolledText(self, wrap=tk.WORD, height=10)
        self.article_input.pack(expand=1, fill='both')
        self.review_output = scrolledtext.ScrolledText(self, wrap=tk.WORD, height=10, bg='light yellow')
        self.review_output.pack(expand=1, fill='both')
        self.review_output.insert(tk.END, "Extracted IOCs will be displayed here...")
        self.review_output.configure(state='disable')  # Make it read-only
        self.review_output.tag_configure("highlight", background="yellow")
        self.parse_button = tk.Button(self, text="Parse IOCs", command=self.parse_iocs)
        self.parse_button.pack(side=tk.BOTTOM, fill='x')
        self.defang_button = tk.Button(self, text="Defang IOCs", command=self.defang_iocs)
        self.defang_button.pack(side=tk.RIGHT, fill='x')
        self.save_button = tk.Button(self, text="Save Group", command=self.save_iocs)
        self.save_button.pack(side=tk.RIGHT, fill='x')
        self.save_folder_button = tk.Button(self, text="Save Individually", command=self.save_iocs_to_folder)
        self.save_folder_button.pack(side=tk.RIGHT, fill='x')
        self.modify_iocs_button = tk.Button(self, text="Add IOC", command=self.add_ioc_to_category)
        self.modify_iocs_button.pack(side=tk.RIGHT, fill='x')
        self.remove_ioc_button = tk.Button(self, text="Remove IOC", command=self.remove_ioc)
        self.remove_ioc_button.pack(side=tk.RIGHT, fill='x')
        #self.file_extension_button = tk.Button(self, text="Identify File Extensions", command=self.identify_file_extensions)
        #self.file_extension_button.pack(side=tk.RIGHT, fill='x')

    def refang(self, value: str) -> str:
        # Refang the defanged IPs and URLs
        value = value.replace('[.]', '.')  # Refang IP
        value = value.replace('hxxp', 'http')
        value = value.replace('hxxps', 'https')  # Refang URL
        return value
    
    def defang(self, value: str) -> str:
        # Defang the IPs and URLs
        value = value.replace('.', '[.]')  # Defang IP
        value = value.replace('http', 'hxxp')
        value = value.replace('https', 'hxxps')  # Defang URL
        return value
        
    def is_filename(self, candidate: str) -> bool:
        return '.' in candidate and not re.match(regexes['domain'], candidate)

    def filter_out_domains(self, candidates):
        """Filter out candidates that match domain patterns."""
        domain_patterns = [regexes["Domains"], regexes["Sub Domains"]]
        
        filtered = []
        
        for candidate in candidates:
            if not any(pattern.search(candidate) for pattern in domain_patterns):
                filtered.append(candidate)
        
        return filtered

    def parse_iocs(self):
        self.article_input.tag_remove("highlight", "1.0", tk.END)
        article = self.article_input.get("1.0", tk.END)
        iocs = {key: set() for key in regexes.keys()}
        self.article_input.tag_configure("highlight", background="yellow")

        for key, regex in regexes.items():
            matches = regex.finditer(article)
            for match in matches:
                print(f"Found match for {key}: {match.group()}")

        for key, regex in regexes.items():
            matches = regex.finditer(article)  # Use finditer to get match objects with start and end positions
            
            for match in matches:
                start_line = article.count('\n', 0, match.start()) + 1  # Calculate the line number of the start of the match
                start_column = match.start() - article.rfind('\n', 0, match.start()) - 1  # Calculate the column number of the start of the match
                end_line = article.count('\n', 0, match.end()) + 1  # Calculate the line number of the end of the match
                end_column = match.end() - article.rfind('\n', 0, match.end()) - 1  # Calculate the column number of the end of the match
                
                start_pos = f"{start_line}.{start_column}"  # Convert start position to Text widget index
                end_pos = f"{end_line}.{end_column}"  # Convert end position to Text widget index
                self.article_input.tag_add("highlight", start_pos, end_pos)  # Highlight the matched text
                
                iocs[key].add(self.refang(match.group()))  # Add the refanged match to the set of IOC

        for sub_domain in iocs['Sub Domains']:
            parts = sub_domain.split('.')
            if len(parts) >= 3:
                domain = '.'.join(parts[-2:])
                iocs['Domains'].add(domain)

        cve_list = [
            'CVE-2000', 'CVE-2001', 'CVE-2002', 'CVE-2003', 'CVE-2004', 'CVE-2005', 
            'CVE-2006', 'CVE-2007', 'CVE-2008', 'CVE-2009', 'CVE-2010', 'CVE-2011', 
            'CVE-2012', 'CVE-2013', 'CVE-2014', 'CVE-2015', 'CVE-2016', 'CVE-2017',  
            'CVE-2019', 'CVE-2020', 'CVE-2021', 'CVE-2022', 'CVE-2023', 'CVE-2024', 
            'CVE-2025', 'CVE-2026', 'CVE-2027', 'CVE-2028', 'CVE-2029', 'CVE-2030', 
            'CVE-2031', 'CVE-2032', 'CVE-2033', 'CVE-2034', 'CVE-2035', 'CVE-2036', 
            'CVE-2037', 'CVE-2038', 'CVE-2039', 'CVE-2040', 'CVE-2041', 'CVE-2042', 
            'CVE-2043', 'CVE-2044', 'CVE-2045', 'CVE-2046', 'CVE-2047', 'CVE-2048', 
            'CVE-2049', 'CVE-2050', 'CVE-2051', 'CVE-2052', 'CVE-2053', 'CVE-2054', 
            'CVE-2055', 'CVE-2056', 'CVE-2057', 'CVE-2058', 'CVE-2059', 'CVE-2060', 'CVE-2018',]
        
        domain_cve_filter = [domain for domain in iocs["Domains"] if not any(domain.startswith(cve) for cve in cve_list)]
        iocs['Domains'] = domain_cve_filter
        
        to_remove = set()  # A set to store domains that need to be removed

        for sub_domain in iocs['Sub Domains']:
            parts = sub_domain.split('.')
            if len(parts) >= 3:  # Ensure it's at least a second-level subdomain
                domain_to_check = '.'.join(parts[:2])  # Take the first two parts and join them
                if domain_to_check in iocs['Domains']:
                    to_remove.add(domain_to_check)

        filtered_domains = {domain for domain in iocs['Domains'] if not re.match(r'^\d{1,3}\.\d{1,3}$', domain)}
        iocs['Domains'] = filtered_domains
        filtered_url = {url for url in iocs['URLs'] if re.match(r'(?i)^(http|hxxp)s?://', url)}
        iocs['URLs'] = filtered_url
        iocs['Domains'] -= to_remove
        self.review_output.configure(state='normal')
        self.review_output.delete("1.0", tk.END)

        for key, values in iocs.items():
            if values:
                self.review_output.insert(tk.END, f"{key}:\n")
                for value in values:
                    self.review_output.insert(tk.END, f"  {value}\n")
                self.review_output.insert(tk.END, "\n")
                    
        self.review_output.configure(state='disabled') 

    def defang_iocs(self):
        # Get the content from the review_output widget
        self.review_output.configure(state='normal')
        content = self.review_output.get("1.0", tk.END)
        defanged_content = self.defang(content)
        self.review_output.delete("1.0", tk.END)
        self.review_output.insert(tk.END, defanged_content)
        self.review_output.configure(state='disabled')

    def save_iocs(self):
        content = self.review_output.get("1.0", tk.END)
        file_path = tk.filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])

        if not file_path:  # If the user cancels the file dialog
            return
       
        with open(file_path, 'w') as file:
            file.write(content.strip())  # strip() is used to remove the trailing newline character
        
        tk.messagebox.showinfo("Success", f"IOCs have been saved to {os.path.basename(file_path)}")

    def save_iocs_to_folder(self):
        # Ask the user for a directory to save the IOCs
        folder_path = tk.filedialog.askdirectory(title="Select Directory to Save IOCs")
        if not folder_path:  # If the user cancels the directory dialog
            return
        
        folder_name = tk.simpledialog.askstring("Input", "Enter the name for the new folder:")
        if not folder_name:  # If the user cancels the input dialog or enters an empty string
            return

        new_folder_path = os.path.join(folder_path, folder_name)
        os.makedirs(new_folder_path, exist_ok=True)  # exist_ok=True will create the folder if it does not exist

        content = self.review_output.get("1.0", tk.END).splitlines()
        current_category = None
        iocs_for_category = []

        for line in content:
            if line.endswith(":"):
                if current_category and iocs_for_category:
                    file_path = os.path.join(new_folder_path, f"{current_category}.txt")
                    with open(file_path, 'w') as file:
                        file.write("\n".join(iocs_for_category))
                    iocs_for_category = []

                current_category = line[:-1]  # Remove the trailing ":"
            else:
                iocs_for_category.append(line.strip)

        if current_category and iocs_for_category:
            file_path = os.path.join(new_folder_path, f"{current_category}.txt")
            with open(file_path, 'w') as file:
                file.write("\n".join(iocs_for_category))

        tk.messagebox.showinfo("Success", f"IOCs have been saved to {new_folder_path}")

    def add_ioc_to_category(self):
        category_window = tk.Toplevel(self)
        category_window.title("Select Category")
        category_listbox = tk.Listbox(category_window)

        for category in regexes.keys():
            category_listbox.insert(tk.END, category)
        category_listbox.pack(pady=10, padx=10)

        def on_add_ioc_button_click():
            selected_category = category_listbox.get(category_listbox.curselection())
            ioc_values = tk.simpledialog.askstring("Input", f"Enter the IOC(s) you want to add to '{selected_category}' (separate by space for multiple):")
            
            if not ioc_values:
                return

            ioc_list = ioc_values.split(" ")
            current_iocs = self.review_output.get("1.0", tk.END).splitlines()
            category_index = None

            for i, line in enumerate(current_iocs):
                if line.startswith(selected_category + ":"):
                    category_index = i
                    break

            if category_index is not None:
                for ioc in ioc_list:
                    current_iocs.insert(category_index + 1, "  " + ioc)
                    category_index += 1  # Update index after each insertion
            else:
                current_iocs.extend([selected_category + ":"])
                current_iocs.extend(["  " + ioc for ioc in ioc_list])

            self.review_output.configure(state='normal')
            self.review_output.delete("1.0", tk.END)
            self.review_output.insert(tk.END, "\n".join(current_iocs))
            self.review_output.configure(state='disabled')
    
            category_window.destroy()

        select_button = tk.Button(category_window, text="Select", command=on_add_ioc_button_click)
        select_button.pack(pady=10)

    def remove_ioc(self):
        category_window = tk.Toplevel(self)
        category_window.title("Select Category")
        category_listbox = tk.Listbox(category_window)

        for category in regexes.keys():
            category_listbox.insert(tk.END, category)
        category_listbox.pack(pady=10, padx=10)

        def on_remove_ioc_button_click():
            selected_category = category_listbox.get(category_listbox.curselection())
            ioc_values = tk.simpledialog.askstring("Input", f"Enter the IOC(s) you want to remove from '{selected_category}' (separate by space for multiple):")

            if not ioc_values:
                return
            
            ioc_list = ioc_values.split(" ")
            current_iocs = self.review_output.get("1.0", tk.END).splitlines()
            category_found = False
            iocs_removed = 0
            i = 0

            while i < len(current_iocs):
                line = current_iocs[i]
                if line.startswith(selected_category + ":"):
                    category_found = True
                elif category_found and line.strip() in ioc_list:
                    del current_iocs[i]
                    iocs_removed += 1
                    i -= 1  # Adjust the index since we removed an element
                i += 1

            if not category_found:
                tk.messagebox.showwarning("Warning", f"The category '{selected_category}' was not found in the list.")
                return
            elif iocs_removed == 0:
                tk.messagebox.showwarning("Warning", "None of the specified IOCs were found in the list.")
                return

            self.review_output.configure(state='normal')
            self.review_output.delete("1.0", tk.END)
            self.review_output.insert(tk.END, "\n".join(current_iocs))
            self.review_output.configure(state='disabled')

            category_window.destroy()

        remove_ioc_button = tk.Button(category_window, text="Remove IOC from Category", command=on_remove_ioc_button_click)
        remove_ioc_button.pack(pady=10)

        def on_remove_from_all_button_click():
            ioc_values = tk.simpledialog.askstring("Input", "Enter the IOC(s) you want to remove from all categories (separate by space for multiple):")
            if not ioc_values:
                return

            ioc_list = ioc_values.split()  # Split by spaces
            current_iocs = self.review_output.get("1.0", tk.END).splitlines()
            iocs_removed = 0

            for ioc in ioc_list:
                i = 0
                while i < len(current_iocs):
                    line = current_iocs[i]
                    if line.strip() == ioc:
                        del current_iocs[i]
                        iocs_removed += 1
                        i -= 1  # Adjust the index since we removed an element
                    i += 1

            if iocs_removed == 0:
                tk.messagebox.showwarning("Warning", "None of the specified IOCs were found in the list.")
                return

            self.review_output.configure(state='normal')
            self.review_output.delete("1.0", tk.END)
            self.review_output.insert(tk.END, "\n".join(current_iocs))
            self.review_output.configure(state='disabled')

            category_window.destroy()

        remove_from_all_button = tk.Button(category_window, text="Remove IOC from All", command=on_remove_from_all_button_click)
        remove_from_all_button.pack(pady=10)

app = IOCExtractor()
app.mainloop()
