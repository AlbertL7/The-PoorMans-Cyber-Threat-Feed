import re
from datetime import datetime
import base64
import json # Needed for jsluice output parsing
import requests
import tkinter as tk
from tkinter import scrolledtext, filedialog, simpledialog, messagebox, ttk # Use ttk for Notebook and Combobox
import os
# from tkinter import ttk # ttk imported above
import shlex # Added for safe command splitting
import platform
import subprocess # Added for running jsluice
import shutil      # Added for checking if jsluice exists
import tempfile    # Added for temporary file handling with jsluice

SEPARATOR_DEFANGS = r"[\(\)\[\]{}<>\\]"
END_PUNCTUATION = r"[\.\?>\"'\)!,}:;\u201d\u2019\uff1e\uff1c\]]*"
ipv4RegExpString = r"""\b(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.|\[\.\])(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.|\[\.\])(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.|\[\.\])(25[0-5]|2[0-4]\d|1\b{2}|[1-9]?\d)\b"""
v6seg = "[a-fA-F\\b]{1,4}"
ipv6RegExpString = (
    "("
    f"(?:{v6seg}:){{7}}{v6seg}|"
    f"(?:{v6seg}:){{7}}(?::{v6seg}|:)|"
    f"(?:{v6seg}:){{6}}(?::{ipv4RegExpString}|(?::{v6seg}){{1,2}}|:)|"
    f"(?:{v6seg}:){{5}}(?::{ipv4RegExpString}|(?::{v6seg}){{1,2}}|:)|"
    f"(?:{v6seg}:){{4}}(?:(?::{v6seg})?:{ipv4RegExpString}|(?::{v6seg}){{1,3}}|:)|"
    f"(?:{v6seg}:){{3}}(?:(?::{v6seg}){{0,2}}:{ipv4RegExpString}|(?::{v6seg}){{1,4}}|:)|"
    f"(?:{v6seg}:){{2}}(?:(?::{v6seg}){{0,3}}:{ipv4RegExpString}|(?::{v6seg}){{1,5}}|:)|"
    f"(?:{v6seg}:){{1}}(?:(?::{v6seg}){{0,4}}:{ipv4RegExpString}|(?::{v6seg}){{1,6}}|:)|"
    f"(?::((?::{v6seg}){{0,5}}:{ipv4RegExpString}|(?::{v6seg}){{1,7}}|:))"
    ")(?:%[0-9a-zA-Z]{1,})?"
)
FILE_EXTENSIONS = r"(doc|docx|pdf|au3|ppt|bin|old|pptx|mui|txt|rtf|xls|diff|xlsx|odt|jpeg|jpg|png|me|info|biz|gif|bmp|svg|tiff|psd|ico|mp3|wav|aac|flac|ogg|m4a|wma|mp4|avi|mkv|flv|mov|wmv|mpeg|zip|rar|7z|tar|gz|bz2|iso|html|htm|css|js|php|py|java|cpp|c|h|cs|sql|db|mdb|xml|json|exe|dll|sys|ini|bat|vbs|dwg|dxf|3ds|max|skp|proj|aep|prproj|veg|cad|stl|step|dat|csv|log|mat|nc|vmdk|vdi|img|qcow2|ttf|otf|fon|bak|tmp|dmp|epub|mobi|azw|azw3|git|svn|sh|bash|ps1|cmd|cfg|conf|yml|yaml|sass|scss|less|jsx|ts|tsx|npm|gem|pip|jar|deb|rpm|swf|lisp|go|rb|r|vmx|ova|ovf|vhdx|hdd|mid|midi|als|ftm|rex|unity|blend|unr|pak|bsp|pem|crt|csr|key|pgp|apk|ipa|app|aab|xapk|md|markdown|tex|bib|cls|vrml|x3d|u3d|ar|sbsar|ovpn|pcf|cisco|rdp|ssh|spss|sav|rdata|dta|do|ftl|twig|jinja|tpl|edml|obj|mtl|dae|abc|c4d|fbx|vrm|glb|gltf|usdz|reg|pol|inf|msi|msp|awk|sed|groovy|lua|tcl|gitignore|gitattributes|hgignore|dockerfile|dockerignore|sqlite|dbf|accdb|ora|frm|chm|mht|epub|mobi|lit|ai|eps|indd|xd|fig|rbw|pl|swift|kt|scala|ics|vcs|ical|zsh|fish)"
TLD = r"(?:com|org|top|ga|ml|info|cf|gq|icu|wang|live|cn|online|host|us|tk|fyi|buzz|net|io|gov|edu|eu|uk|de|fr|me|es|bid|shop|it|nl|ru|jp|in|br|au|ca|mx|nz|tv|cc|co|ro|us|asia|mobi|pro|tel|aero|travel|xyz|dagree|club|online|site|store|app|blog|design|tech|guru|ninja|news|media|network|agency|digital|email|link|click|world|today|solutions|tools|company|photography|tips|technology|works|zone|watch|video|guide|rodeo|life|chat|expert|haus|marketing|center|systems|academy|training|services|support|education|church|community|foundation|charity|ngo|ong|social|events|productions|fun|games|reviews|business|gdn|enterprises|international|land|properties|rentals|ventures|holdings|luxury|boutique|accountants|agency|associates|attorney|cc|construction|contractors|credit|dentist|engineer|equipment|estate|financial|florist|gallery|graphics|law|lawyer|management|marketing|media|photography|photos|productions|properties|realtor|realty|solutions|studio|systems|technology|ventures|vet|veterinarian|aaa|aarp|abb|abbott|abbvie|abc|able|abogado|abudhabi|ac|academy|accenture|accountant|accountants|aco|actor|ad|ads|adult|ae|aeg|aero|aetna|af|afl|africa|ag|agakhan|agency|ai|aig|airbus|airforce|airtel|akdn|al|alibaba|alipay|allfinanz|allstate|ally|alsace|alstom|am|amazon|americanexpress|americanfamily|amex|amfam|amica|amsterdam|analytics|android|anquan|anz|ao|aol|apartments|app|apple|aq|aquarelle|ar|arab|aramco|archi|army|arpa|art|arte|as|asda|asia|associates|at|athleta|attorney|au|auction|audi|audible|audio|auspost|author|auto|autos|avianca|aw|aws|ax|axa|az|azure|ba|baby|baidu|banamex|bananarepublic|band|bank|bar|barcelona|barclaycard|barclays|barefoot|bargains|baseball|basketball|bauhaus|bayern|bb|bbc|bbt|bbva|bcg|bcn|bd|be|beats|beauty|beer|bentley|berlin|best|bestbuy|bet|bf|bg|bh|bharti|bi|bible|bid|bike|bing|bingo|bio|biz|bj|black|blackfriday|blockbuster|blog|bloomberg|blue|bm|bms|bmw|bn|bnpparibas|bo|boats|boehringer|bofa|bom|bond|boo|book|booking|bosch|bostik|boston|bot|boutique|box|br|bradesco|bridgestone|broadway|broker|brother|brussels|bs|bt|build|builders|business|buy|buzz|bv|bw|by|bz|bzh|ca|cab|cafe|cal|call|calvinklein|cam|camera|camp|canon|capetown|capital|capitalone|car|caravan|cards|care|career|careers|cars|casa|case|cash|casino|cat|catering|catholic|cba|cbn|cbre|cbs|cc|cd|center|ceo|cern|cf|cfa|cfd|cg|ch|chanel|channel|charity|chase|chat|cheap|chintai|christmas|chrome|church|ci|cipriani|circle|cisco|citadel|citi|citic|city|cityeats|ck|cl|claims|cleaning|click|clinic|clinique|clothing|cloud|club|clubmed|cm|cn|co|coach|codes|coffee|college|cologne|com|comcast|commbank|community|company|compare|computer|comsec|condos|construction|consulting|contact|contractors|cooking|cool|coop|corsica|country|coupon|coupons|courses|cpa|cr|credit|creditcard|creditunion|cricket|crown|crs|cruise|cruises|cu|cuisinella|cv|cw|cx|cy|cymru|cyou|cz|dabur|dad|dance|data|date|dating|datsun|day|dclk|dds|de|deal|dealer|deals|degree|delivery|dell|deloitte|delta|democrat|dental|dentist|desi|design|dev|dhl|diamonds|diet|digital|direct|directory|discount|discover|dish|diy|dj|dk|dm|dnp|do|docs|doctor|dog|domains|dot|download|drive|dtv|dubai|dunlop|dupont|durban|dvag|dvr|dz|earth|eat|ec|eco|edeka|edu|education|ee|eg|email|emerck|energy|engineer|engineering|enterprises|epson|equipment|er|ericsson|erni|es|esq|estate|et|etisalat|eu|eurovision|eus|events|exchange|expert|exposed|express|extraspace|fage|fail|fairwinds|faith|family|fan|fans|farm|farmers|fashion|fast|fedex|feedback|ferrari|ferrero|fi|fidelity|fido|film|final|finance|financial|fire|firestone|firmdale|fish|fishing|fit|fitness|fj|fk|flickr|flights|flir|florist|flowers|fly|fm|fo|foo|food|football|ford|forex|forsale|forum|foundation|fox|fr|free|fresenius|frl|frogans|frontdoor|frontier|ftr|fujitsu|fun|fund|furniture|futbol|fyi|ga|gal|gallery|gallo|gallup|game|games|gap|garden|gay|gb|gbiz|gd|gdn|ge|gea|gent|genting|george|gf|gg|ggee|gh|gi|gift|gifts|gives|giving|gl|glass|gle|global|globo|gm|gmail|gmbh|gmo|gmx|gn|godaddy|gold|goldpoint|golf|goo|goodyear|goog|google|gop|got|gov|gp|gq|gr|grainger|graphics|gratis|green|gripe|grocery|group|gs|gt|gu|guardian|gucci|guge|guide|guitars|guru|gw|gy|hair|hamburg|hangout|haus|hbo|hdfc|hdfcbank|health|healthcare|help|helsinki|here|hermes|hiphop|hisamitsu|hitachi|hiv|hk|hkt|hm|hn|hockey|holdings|holiday|homedepot|homegoods|homes|homesense|honda|horse|hospital|host|hosting|hot|hotels|hotmail|house|how|hr|hsbc|ht|hu|hughes|hyatt|hyundai|ibm|icbc|ice|icu|id|ie|ieee|ifm|ikano|il|im|imamat|imdb|immo|immobilien|in|inc|industries|infiniti|info|ing|ink|institute|insurance|insure|int|international|intuit|investments|io|ipiranga|iq|ir|irish|is|ismaili|ist|istanbul|it|itau|itv|jaguar|java|jcb|je|jeep|jetzt|jewelry|jio|jll|jm|jmp|jnj|jo|jobs|joburg|jot|joy|jp|jpmorgan|jprs|juegos|juniper|kaufen|kddi|ke|kerryhotels|kerrylogistics|kerryproperties|kfh|kg|kh|ki|kia|kids|kim|kinder|kindle|kitchen|kiwi|km|kn|koeln|komatsu|kosher|kp|kpmg|kpn|kr|krd|kred|kuokgroup|kw|ky|kyoto|kz|la|lacaixa|lamborghini|lamer|lancaster|land|landrover|lanxess|lasalle|lat|latino|latrobe|law|lawyer|lb|lc|lds|lease|leclerc|lefrak|legal|lego|lexus|lgbt|li|lidl|life|lifeinsurance|lifestyle|lighting|like|lilly|limited|limo|lincoln|link|lipsy|live|living|lk|llc|llp|loan|loans|locker|locus|lol|london|lotte|lotto|love|lpl|lplfinancial|lr|ls|lt|ltd|ltda|lu|lundbeck|luxe|luxury|lv|ly|ma|madrid|maif|maison|makeup|man|management|mango|map|market|marketing|markets|marriott|marshalls|mattel|mba|mc|mckinsey|md|me|med|media|meet|melbourne|meme|memorial|men|menu|merckmsd|mg|mh|miami|microsoft|mil|mini|mint|mit|mitsubishi|mk|ml|mlb|mls|mm|mma|mn|mo|mobi|mobile|moda|moe|moi|mom|monash|money|monster|mormon|mortgage|moscow|moto|motorcycles|mov|movie|mp|mq|mr|ms|msd|mt|mtn|mtr|mu|museum|music|mv|mw|mx|my|mz|na|nab|nagoya|name|natura|navy|nba|nc|ne|nec|net|netbank|netflix|network|neustar|new|news|next|nextdirect|nexus|nf|nfl|ng|ngo|nhk|ni|nico|nike|nikon|ninja|nissan|nissay|nl|no|nokia|norton|now|nowruz|nowtv|np|nr|nra|nrw|ntt|nu|nyc|nz|obi|observer|office|okinawa|olayan|olayangroup|oldnavy|ollo|om|omega|one|ong|onl|online|ooo|open|oracle|orange|org|organic|origins|osaka|otsuka|ott|ovh|pa|page|panasonic|paris|pars|partners|parts|party|pay|pccw|pe|pet|pf|pfizer|pg|ph|pharmacy|phd|philips|phone|photo|photography|photos|physio|pics|pictet|pictures|pid|pin|ping|pink|pioneer|pizza|pk|pl|place|play|playstation|plumbing|plus|pm|pn|pnc|pohl|poker|politie|porn|post|pr|pramerica|praxi|press|prime|pro|prod|productions|prof|progressive|promo|properties|property|protection|pru|prudential|ps|pt|pub|pw|pwc|qa|qpon|quebec|quest|racing|radio|re|read|realestate|realtor|realty|recipes|red|redstone|redumbrella|rehab|reise|reisen|reit|reliance|ren|rent|rentals|repair|report|republican|rest|restaurant|review|reviews|rexroth|rich|richardli|ricoh|ril|rio|rip|ro|rocher|rocks|rodeo|rogers|room|rs|rsvp|ru|rugby|ruhr|run|rw|rwe|ryukyu|sa|saarland|safe|safety|sakura|sale|salon|samsclub|samsung|sandvik|sandvikcoromant|sanofi|sap|sarl|sas|save|saxo|sb|sbi|sbs|sc|sca|scb|schaeffler|schmidt|scholarships|school|schule|schwarz|science|scot|sd|se|search|seat|secure|security|seek|select|sener|services|seven|sew|sex|sexy|sfr|sg|sh|shangrila|sharp|shaw|shell|shia|shiksha|shoes|shop|shopping|shouji|show|showtime|si|silk|sina|singles|site|sj|sk|ski|skin|sky|skype|sl|sling|sm|smart|smile|sn|sncf|so|soccer|social|softbank|software|sohu|solar|solutions|song|sony|soy|spa|space|sport|spot|sr|srl|ss|st|stada|staples|star|statebank|statefarm|stc|stcgroup|stockholm|storage|store|stream|studio|study|style|su|sucks|supplies|supply|support|surf|surgery|suzuki|sv|swatch|swiss|sx|sy|sydney|systems|sz|tab|taipei|talk|taobao|target|tatamotors|tatar|tattoo|tax|taxi|tc|tci|td|tdk|team|tech|technology|tel|temasek|tennis|teva|tf|tg|th|thd|theater|theatre|tiaa|tickets|tienda|tips|tires|tirol|tj|tjmaxx|tjx|tk|tkmaxx|tl|tm|tmall|tn|to|today|tokyo|tools|top|toray|toshiba|total|tours|town|toyota|toys|tr|trade|trading|training|travel|travelers|travelersinsurance|trust|trv|tt|tube|tui|tunes|tushu|tv|tvs|tw|tz|ua|ubank|ubs|ug|uk|unicom|university|uno|uol|ups|us|uy|uz|va|vacations|vana|vanguard|vc|ve|vegas|ventures|verisign|versicherung|vet|vg|vi|viajes|video|vig|viking|villas|vin|vip|virgin|visa|vision|viva|vivo|vlaanderen|vn|vodka|volkswagen|volvo|vote|voting|voto|voyage|vu|wales|walmart|walter|wang|wanggou|watch|watches|weather|weatherchannel|webcam|weber|website|wed|wedding|weibo|weir|wf|whoswho|wien|wiki|williamhill|win|windows|wine|winners|wme|wolterskluwer|woodside|work|works|world|wow|ws|wtc|wtf|xbox|xerox|xfinity|xihuan|xin|xn--11b4c3d|xn--1ck2e1b|xn--1qqw23a|xn--2scrj9c|xn--30rr7y|xn--3bst00m|xn--3ds443g|xn--3e0b707e|xn--3hcrj9c|xn--3pxu8k|xn--42c2d9a|xn--45br5cyl|xn--45brj9c|xn--45q11c|xn--4dbrk0ce|xn--4gbrim|xn--54b7fta0cc|xn--55qw42g|xn--55qx5d|xn--5su34j936bgsg|xn--5tzm5g|xn--6frz82g|xn--6qq986b3xl|xn--80adxhks|xn--80ao21a|xn--80aqecdr1a|xn--80asehdb|xn--80aswg|xn--8y0a063a|xn--90a3ac|xn--90ae|xn--90ais|xn--9dbq2a|xn--9et52u|xn--9krt00a|xn--b4w605ferd|xn--bck1b9a5dre4c|xn--c1avg|xn--c2br7g|xn--cck2b3b|xn--cckwcxetd|xn--cg4bki|xn--clchc0ea0b2g2a9gcd|xn--czr694b|xn--czrs0t|xn--czru2d|xn--d1acj3b|xn--d1alf|xn--e1a4c|xn--eckvdtc9d|xn--efvy88h|xn--fct429k|xn--fhbei|xn--fiq228c5hs|xn--fiq64b|xn--fiqs8s|xn--fiqz9s|xn--fjq720a|xn--flw351e|xn--fpcrj9c3d|xn--fzc2c9e2c|xn--fzys8d69uvgm|xn--g2xx48c|xn--gckr3f0f|xn--gecrj9c|xn--gk3at1e|xn--h2breg3eve|xn--h2brj9c|xn--h2brj9c8c|xn--hxt814e|xn--i1b6b1a6a2e|xn--imr513n|xn--io0a7i|xn--j1aef|xn--j1amh|xn--j6w193g|xn--jlq480n2rg|xn--jvr189m|xn--kcrx77d1x4a|xn--kprw13d|xn--kpry57d|xn--kput3i|xn--l1acc|xn--lgbbat1ad8j|xn--mgb9awbf|xn--mgba3a3ejt|xn--mgba3a4f16a|xn--mgba7c0bbn0a|xn--mgbaakc7dvf|xn--mgbaam7a8h|xn--mgbab2bd|xn--mgbah1a3hjkrd|xn--mgbai9azgqp6j|xn--mgbayh7gpa|xn--mgbbh1a|xn--mgbbh1a71e|xn--mgbc0a9azcg|xn--mgbca7dzdo|xn--mgbcpq6gpa1a|xn--mgberp4a5d4ar|xn--mgbgu82a|xn--mgbi4ecexp|xn--mgbpl2fh|xn--mgbt3dhd|xn--mgbtx2b|xn--mgbx4cd0ab|xn--mix891f|xn--mk1bu44c|xn--mxtq1m|xn--ngbc5azd|xn--ngbe9e0a|xn--ngbrx|xn--node|xn--nqv7f|xn--nqv7fs00ema|xn--nyqy26a|xn--o3cw4h|xn--ogbpf8fl|xn--otu796d|xn--p1acf|xn--p1ai|xn--pgbs0dh|xn--pssy2u|xn--q7ce6a|xn--q9jyb4c|xn--qcka1pmc|xn--qxa6a|xn--qxam|xn--rhqv96g|xn--rovu88b|xn--rvc1e0am3e|xn--s9brj9c|xn--ses554g|xn--t60b56a|xn--tckwe|xn--tiq49xqyj|xn--unup4y|xn--vermgensberater-ctb|xn--vermgensberatung-pwb|xn--vhquv|xn--vuq861b|xn--w4r85el8fhu5dnra|xn--w4rs40l|xn--wgbh1c|xn--wgbl6a|xn--xhq521b|xn--xkc2al3hye2a|xn--xkc2dl3a5ee0h|xn--y9a3aq|xn--yfro4i67o|xn--ygbi2ammx|xn--zfr164b|xxx|xyz|yachts|yahoo|yamaxun|yandex|ye|yodobashi|yoga|yokohama|you|youtube|yt|yun|za|zappos|zara|zero|zip|zm|zone|zuerich|zw)"

regexes = {
    'IPv4': re.compile(r'\b(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.|\[\.\])(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.|\[\.\])(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.|\[\.\])(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'),
    # 'IPv6': re.compile(ipv6RegExpString, re.IGNORECASE),
    'Domains': re.compile((r"(?<![@a-zA-Z0-9._%+-])([a-zA-Z0-9\-]+(?:\.|\[\.\]){0})\b").format(TLD)),
    'Sub Domains': re.compile(r'(?<![@a-zA-Z0-9._%+-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.|\[\.]))+[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.|\[\.])[a-zA-Z]{2,}'),
    'URLs': re.compile(r"((?!.*[a-zA-Z0-9]{16,}(\[\.\]|\.)onion\/)[fhstu]\S\S?[px]s?(?::\/\/|:\\\\|\[:\]\/\/|\[:\/\/\]|:?__)(?:\x20|" + SEPARATOR_DEFANGS + r")*\w\S+?(?:\x20[\/\.][^\.\/\s]\S*?)*)(?=\s|[^\x00-\x7F]|$)", re.IGNORECASE | re.VERBOSE | re.UNICODE),
    'IP URL': re.compile(r'hxxps?:\/\/(?:\d{1,3}\.|\[\.\])?(?:\d{1,3}\.|\[\.\])?(?:\d{1,3}\.|\[\.\])?\d{1,3}(?:\[\.\]\d{1,3})?\/\d+\/[a-f0-9]+'),
    'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
    'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
    'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
    'sha512': re.compile(r'\b[A-Fa-f0-9]{128}\b'),
    'SS-Deep':re.compile(r'\b(?=.{60})\d+:[A-Za-z0-9/+]+:[A-Za-z0-9/+]+\b'),
    'CVEs': re.compile(r'(?:CVE-\d{4}-\d{4,}|CVE[\s\[\(]\d{4}-\d{4,}[\]\)])'),
    'File Names Found Outside Quotes': re.compile((r"""(?<=[\"\'])+\s[^\"\']+\.{0}(?=[\"\'])|(?<![\"\'])\b[^'\" \t\n\r\f\v/\-\\]+?\.{0}\b(?![\"\'])""").format(FILE_EXTENSIONS), re.VERBOSE),
    'File Names Found Inside Quotes': re.compile((r"""(?<=[\"\'])+\s[^\"\']+\.{0}(?=[\"\'])|(?<![\"\'])\b[^'\" \t\n\r\f\v/\-\\]+?\.{0}""").format(FILE_EXTENSIONS), re.VERBOSE),
    'Email Addresses': re.compile(r"""([a-z0-9_.+-]+[\(\[{\x20]*(?:(?:(?:\x20*""" + SEPARATOR_DEFANGS + r"""\x20*)*\.(?:\x20*""" + SEPARATOR_DEFANGS + r"""\x20*)*|\W+dot\W+)[a-z0-9-]+?)*[a-z0-9_.+-]+[\(\[{\x20]*(?:@|\Wat\W)[\)\]}\x20]*[a-z0-9-]+(?:(?:(?:\x20*""" + SEPARATOR_DEFANGS + r"""\x20*)*\.(?:\x20*""" + SEPARATOR_DEFANGS + r"""\x20*)*|\W+dot\W+)[a-z0-9-]+?)+)""" + END_PUNCTUATION + r"""(?=\s|$)""", re.IGNORECASE | re.VERBOSE | re.UNICODE,),
    'Registry': re.compile(r'\b((HKLM|HKCU)\\[\\A-Za-z0-9-_]+)\b'),
    'Mac Address': re.compile(r'\b(?:[A-Fa-f0-9]{2}([-:]))(?:[A-Fa-f0-9]{2}\1){4}[A-Fa-f0-9]{2}\b'),
    'Bitcoin Addresses': re.compile(r'\b[13][a-km-zA-HJ-NP-Z0-9]{26,33}\b'),
    'Dark Web': re.compile(r'[a-z2-7]{16,56}\.onion\b'),
    'Yara Rules': re.compile(r"""(?:^|\s)((?:\s*?import\s+?"[^\r\n]*?[\r\n]+|\s*?include\s+?"[^\r\n]*?[\r\n]+|\s*?//[^\r\n]*[\r\n]+|\s*?/\*.*?\*/\s*?)*(?:\s*?private\s+|\s*?global\s+)*rule\s*?\w+\s*?(?::[\s\w]+)?\s+\{.*?condition\s*?:.*?\s*\})(?:$|\s)""",re.MULTILINE | re.DOTALL | re.VERBOSE,),
}


class IOCExtractor(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IOC Extractor (Improved GUI - Original Regex + Jsluice)")
        self.geometry("1600x900")

        # VT API Key storage 
        self.vt_api_key = None
        self.found_iocs = {} # For parsed IOCs

        # --- Check for jsluice ---
        self.jsluice_path = shutil.which('jsluice')
        self.jsluice_needs_python = False
        self.jsluice_executable_or_script = None # Initialize to None
        if self.jsluice_path:
            # *** ADDED: Get the base name ***
            self.jsluice_executable_or_script = os.path.basename(self.jsluice_path) # Store the name
            if self.jsluice_path.lower().endswith('.py'):
                py_path = shutil.which('python') or shutil.which('python3')
                if py_path:
                    self.jsluice_needs_python = True
                    self.jsluice_base_command = [py_path, self.jsluice_path]
                else:
                    self.jsluice_path = None # Disable jsluice if python is needed but not found
                    self.jsluice_executable_or_script = None # Reset if path becomes None
                    messagebox.showwarning("Jsluice Warning", "Found jsluice.py but no 'python'/'python3' executable.\nJsluice disabled.")
            # *** MOVED: This else belongs to the outer if self.jsluice_path ***
            else: # It's an executable, not a .py script
                self.jsluice_base_command = [self.jsluice_path]
        # *** ADDED: Handle case where jsluice is not found at all ***
        else:
             self.jsluice_base_command = [] # Or some default indicating not found

        # --- Top Frame for Find/Replace ---
        self.find_replace_frame = tk.Frame(self, bg='light grey')
        self.find_replace_frame.pack(side=tk.TOP, fill='x', padx=5, pady=5)
        self.find_label = tk.Label(self.find_replace_frame, text="Find:", bg='light grey'); self.find_label.grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.find_entry = tk.Entry(self.find_replace_frame, width=40); self.find_entry.grid(row=0, column=1, padx=5, pady=2, sticky='ew')
        self.find_entry.bind("<KeyRelease>", lambda e: self.highlight_text())
        self.replace_label = tk.Label(self.find_replace_frame, text="Replace:", bg='light grey'); self.replace_label.grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.replace_entry = tk.Entry(self.find_replace_frame, width=40); self.replace_entry.grid(row=1, column=1, padx=5, pady=2, sticky='ew')
        self.find_replace_button = tk.Button(self.find_replace_frame, text="Find & Replace", command=self.find_and_replace, fg='black', bg='deep sky blue'); self.find_replace_button.grid(row=0, column=2, padx=5, pady=2, sticky='ew')
        self.regex_var = tk.IntVar()
        self.regex_checkbox = tk.Checkbutton(self.find_replace_frame, text="Use Regex", variable=self.regex_var, bg='light grey', command=self.highlight_text); self.regex_checkbox.grid(row=1, column=2, padx=5, pady=2, sticky='w')
        self.save_input_button = tk.Button(self.find_replace_frame, text="Save Input", command=self.save_input_text, fg='black', bg='slate grey'); self.save_input_button.grid(row=0, column=3, padx=5, pady=2, sticky='ew')
        self.clear_input_button = tk.Button(self.find_replace_frame, text="Clear Input", command=self.clear_input_text, fg='black', bg='red3'); self.clear_input_button.grid(row=1, column=3, padx=5, pady=2, sticky='ew')
        self.find_replace_frame.grid_columnconfigure(1, weight=1)

        # --- Main Paned Window for Input/Output ---
        self.main_pane = tk.PanedWindow(self, orient=tk.VERTICAL, sashrelief=tk.RAISED, sashwidth=5)
        self.main_pane.pack(expand=True, fill='both', padx=5, pady=5)

        # --- Input Area ---
        self.input_frame = tk.Frame(self.main_pane)
        self.article_input = scrolledtext.ScrolledText(self.input_frame, wrap=tk.WORD, height=15, bg='light grey', fg='black', undo=True)
        self.article_input.pack(expand=True, fill='both')
        self.article_input.insert(tk.END, "Input Text Here... Use hot keys for copy & paste")
        self.article_input.bind("<FocusIn>", self.on_input_focus_in)
        self.article_input.bind("<FocusOut>", self.on_input_focus_out)
        
        # Configure Highlight Tags
        self.article_input.tag_configure("highlight", background="light green") # Tag for Find feature
        self.article_input.tag_configure("ioc_highlight", background="orange") # Tag for Parsed IOCs
        self.main_pane.add(self.input_frame, stretch="always")

        # --- Output Frame (holds IOCs, VT, Jsluice) ---
        self.output_notebook = ttk.Notebook(self.main_pane)

        # --- Minimal Tab Color Styling ---
        try:
            style = ttk.Style()
            style.configure('TNotebook.Tab', background="light grey", foreground="black")
            style.map('TNotebook.Tab', background=[('selected', "dark slate grey")], foreground=[('selected', "black")])
        except Exception as e:
            print(f"Info: Could not apply custom tab styling - {e}")
        # --- End Minimal Tab Color Styling ---

        # --- Add the Tabs ---
        # IOC Tab
        self.review_frame = tk.Frame(self.output_notebook)
        self.review_frame.pack(expand=True, fill='both')
        self.review_output = scrolledtext.ScrolledText(self.review_frame, wrap=tk.WORD, height=10, bg='grey10', fg='snow')
        self.review_output.pack(side=tk.TOP, expand=True, fill='both')
        self.review_output.insert(tk.END, "Extracted IOCs will be displayed here... Click Parse IOCs\n\nTo clean up output, I find that getting rid of the following with Find & Replace helps a lot when dealing with Javascript from view page source (etc):\n\t<\n\t>\n\t\'\n\t\"")
        self.review_output.configure(state='disabled')
        self.review_output.tag_configure("bold", font=("Arial", 12, "bold"))
        self.review_output.tag_configure("error", foreground="red")
        self.output_notebook.add(self.review_frame, text="IOC Review")

        # VirusTotal Tab
        self.vt_frame_tab = tk.Frame(self.output_notebook)
        self.vt_frame_tab.pack(expand=True, fill='both')
        self.vt_results_output = scrolledtext.ScrolledText(self.vt_frame_tab, wrap=tk.WORD, height=10, bg='grey10', fg='snow')
        self.vt_results_output.pack(side=tk.TOP, expand=True, fill='both')
        # Updated VT Instructions
        self.vt_results_output.insert(tk.END, """VirusTotal results will be displayed here...

How to Use VT Buttons:

1. Paste text containing IOCs (IPs, URLs, Hashes) into the input box above.
2. Click **`Parse IOCs`**. Parsed IOCs appear in the 'IOC Review' tab and are highlighted orange in the input box.
3. **In the 'IOC Review' tab**, select (highlight) the IOC(s) you want to check.
    - You can highlight more than one IOC at a time to submit and not have to worry about new lines or byte prefixes.
4. Click the desired **`VT...`** button below.
5. Enter your VT API Key **when prompted** (usually only needed once per session).
6. Results will appear here.""")
        self.vt_results_output.configure(state='disabled')
        # Define bold tag for VT output area
        self.vt_results_output.tag_configure("bold", font=("Arial", 10, "bold"))
        # Define error tag for VT output area
        self.vt_results_output.tag_configure("error", foreground="red")
        self.output_notebook.add(self.vt_frame_tab, text="VirusTotal Results")

        # Jsluice Tab
        self.jsluice_frame_tab = tk.Frame(self.output_notebook) # Frame to hold text
        self.jsluice_frame_tab.pack(expand=True, fill='both') # Pack the frame
        self.jsluice_results_output = scrolledtext.ScrolledText(self.jsluice_frame_tab, wrap=tk.WORD, height=10, bg='grey10', fg='snow')
        self.jsluice_results_output.pack(side=tk.TOP, expand=True, fill='both') # Pack text area at the top
        jsluice_initial_help_text = """Jsluice results will appear here.

Usage:
  jsluice <mode> [options] [file...]

Modes:
  urls      Extract URLs and paths
  secrets   Extract secrets and other interesting bits
  tree      Print syntax trees for input files
  query     Run tree-sitter a query against input files
  format    Format JavaScript source using jsbeautifier-go

Global options:
  -c, --concurrency int        Number of files to process concurrently (default 1)
  -C, --cookie string          Cookies to use when making requests to the specified HTTP based arguments
  -H, --header string          Headers to use when making requests to the specified HTTP based arguments (can be specified multiple times)
  -P, --placeholder string     Set the expression placeholder to a custom string (default 'EXPR')
  -j, --raw-input              Read raw JavaScript source from stdin
  -w, --warc                   Treat the input files as WARC (Web ARChive) files
  -i, --no-check-certificate   Ignore validation of server certificates

URLs mode:
  -I, --ignore-strings         Ignore matches from string literals
  -S, --include-source         Include the source code where the URL was found
  -R, --resolve-paths <url>    Resolve relative paths using the absolute URL provided
  -u, --unique                 Only output each URL once per input file

Secrets mode:
  -p, --patterns <file>        JSON file containing user-defined secret patterns to look for

Query mode:
  -q, --query <query>          Tree sitter query to run; e.g. '(string) @matches'
  -r, --raw-output             Do not convert values to native types
  -f, --include-filename       Include the filename in the output
  -F, --format                 Format source code in the output

Examples:
  jsluice urls -C 'auth=true; user=admin;' -H 'Specific-Header-One: true' -H 'Specific-Header-Two: false' local_file.js https://remote.host/example.js
  jsluice query -q '(object) @m' one.js two.js
  find . -name '*.js' | jsluice secrets -c 5 --patterns=apikeys.json"""
        self.jsluice_results_output.insert(tk.END, jsluice_initial_help_text)
        if not self.jsluice_path:
            self.jsluice_results_output.insert(tk.END, "\n\n-------\nWARNING: jsluice command not found ... \n-------")
        self.jsluice_results_output.configure(state='disabled')
        self.output_notebook.add(self.jsluice_frame_tab, text="Jsluice Analysis")

        self.main_pane.add(self.output_notebook, stretch="always")

        # *** RENAME: General Shell Command Tab ***
        self.shell_command_frame = tk.Frame(self.output_notebook, bg='grey15') # Use a frame for structure
        self.shell_command_frame.pack(expand=True, fill='both')
        
        # Output Area
        self.shell_command_output = scrolledtext.ScrolledText(self.shell_command_frame, wrap=tk.WORD, height=10, bg='grey10', fg='light cyan')
        self.shell_command_output.pack(side=tk.TOP, expand=True, fill='both', padx=5, pady=5)
        
        # Updated initial text
        self.shell_command_output.insert(tk.END, "Enter any shell command below (e.g., cat file.js | jsluice urls, or echo '...' | grep ...)\n")
        self.shell_command_output.configure(state='disabled')
        
        # Input Area Frame
        shell_input_frame = tk.Frame(self.shell_command_frame, bg='grey15')
        shell_input_frame.pack(side=tk.BOTTOM, fill='x', padx=5, pady=(0,5))
        
        # Label
        shell_cmd_label = tk.Label(shell_input_frame, text="Command:", bg='grey15', fg='white') # Renamed Label text
        shell_cmd_label.pack(side=tk.LEFT, padx=(0,5))
        
        # Entry
        self.shell_command_entry = tk.Entry(shell_input_frame, bg='grey30', fg='white', insertbackground='white') # Renamed Entry variable
        self.shell_command_entry.pack(side=tk.LEFT, expand=True, fill='x', padx=5)
        
        # *** Bind Enter key to the NEW method name ***
        self.shell_command_entry.bind("<Return>", self.run_shell_command_event)
        
        # Run Button - Always enabled now
        self.shell_command_button = tk.Button(shell_input_frame, text="Run Shell", command=self.run_shell_command, bg='dark orange', fg='black') # Renamed Button, changed text/color
        self.shell_command_button.pack(side=tk.RIGHT, padx=(5,0))
        
        # Add the tab to notebook with new name
        self.output_notebook.add(self.shell_command_frame, text="Shell Command") # Renamed Tab Text
        self.main_pane.add(self.output_notebook, stretch="always")

        # ***** START NEW BOTTOM BUTTON LAYOUT *****
        # --- Bottom Row 3: Clear Buttons ---
        self.clear_button_frame = tk.Frame(self); self.clear_button_frame.pack(side=tk.BOTTOM, fill='x', padx=5, pady=2)
        self.clear_ioc_button = tk.Button(self.clear_button_frame, text="Clear IOCs", command=self.clear_review_output, fg='black', bg='red3'); self.clear_ioc_button.pack(side=tk.LEFT, padx=2, pady=2)
        self.clear_vt_button = tk.Button(self.clear_button_frame, text="Clear VT", command=self.clear_vt_output, fg='black', bg='red3'); self.clear_vt_button.pack(side=tk.LEFT, padx=2, pady=2)
        self.clear_jsluice_button = tk.Button(self.clear_button_frame, text="Clear Jsluice", command=self.clear_jsluice_output, fg='black', bg='red3'); self.clear_jsluice_button.pack(side=tk.LEFT, padx=2, pady=2)

        # --- Bottom Row 2: VT Buttons ---
        self.vt_button_frame = tk.Frame(self); self.vt_button_frame.pack(side=tk.BOTTOM, fill='x', padx=5, pady=2)
        
        # Link to NEW VT Functions
        self.vt_button = tk.Button(self.vt_button_frame, text="VT Check Selected", command=self.on_vt_button_click, fg='black', bg='purple1'); self.vt_button.pack(side=tk.LEFT, padx=2, pady=2)
        self.submit_url_button = tk.Button(self.vt_button_frame, text="VT Submit URL(s)", command=self.submit_url_for_analysis, fg='black', bg='purple1'); self.submit_url_button.pack(side=tk.LEFT, padx=2, pady=2)
        
        # VT Hash Check button calls on_vt_button_click, which handles hashes via query_virustotal
        self.submit_hash_button = tk.Button(self.vt_button_frame, text="VT Check Hash(es)", command=self.on_vt_button_click, fg='black', bg='purple1'); self.submit_hash_button.pack(side=tk.LEFT, padx=2, pady=2)
        self.all_hashes_button = tk.Button(self.vt_button_frame, text="VT Get Hash Details", command=self.get_all_hash_details, fg='black', bg='purple1'); self.all_hashes_button.pack(side=tk.LEFT, padx=2, pady=2)
        self.mitre_button = tk.Button(self.vt_button_frame, text="Get MITRE TTPs", command=self.submit_for_mitre_ttps, fg='black', bg='purple1'); self.mitre_button.pack(side=tk.LEFT, padx=2, pady=2)

        # --- Bottom Row 1: Parse, Jsluice Controls, Save ---
        # (Row 1 setup remains the same) ...
        self.bottom_button_frame_row1 = tk.Frame(self); self.bottom_button_frame_row1.pack(side=tk.BOTTOM, fill='x', padx=5, pady=(5, 2))
        self.left_button_frame = tk.Frame(self.bottom_button_frame_row1); self.left_button_frame.pack(side=tk.LEFT, fill='x', expand=False, padx=(0, 5))
        self.parse_button = tk.Button(self.left_button_frame, text="Parse IOCs", command=self.parse_iocs, fg='black', bg='seagreen3'); self.parse_button.pack(side=tk.LEFT, padx=2, pady=2)
        self.defang_button = tk.Button(self.left_button_frame, text="Defang IOCs", command=self.defang_iocs, fg='black', bg='seagreen3'); self.defang_button.pack(side=tk.LEFT, padx=2, pady=2)
        self.refang_button = tk.Button(self.left_button_frame, text="Refang IOCs", command=self.refang_iocs, fg='black', bg='seagreen3'); self.refang_button.pack(side=tk.LEFT, padx=2, pady=2)
        
        # Jsluice controls frame - ADD Checkbox here
        self.jsluice_control_frame = tk.Frame(self.bottom_button_frame_row1); self.jsluice_control_frame.pack(side=tk.LEFT, fill='x', expand=True, padx=5)
        jsluice_mode_label = tk.Label(self.jsluice_control_frame, text="Mode:"); jsluice_mode_label.pack(side=tk.LEFT, padx=(0, 2))
        self.jsluice_modes = ['urls', 'secrets', 'tree', 'query', 'format']
        self.jsluice_mode_combobox = ttk.Combobox(self.jsluice_control_frame, values=self.jsluice_modes, state="readonly", width=10); self.jsluice_mode_combobox.pack(side=tk.LEFT, padx=2); self.jsluice_mode_combobox.set('urls')
        jsluice_options_label = tk.Label(self.jsluice_control_frame, text="Options:"); jsluice_options_label.pack(side=tk.LEFT, padx=(5, 2))
        self.jsluice_options_entry = tk.Entry(self.jsluice_control_frame, width=30); self.jsluice_options_entry.pack(side=tk.LEFT, padx=2, fill='x', expand=True)
        self.jsluice_help_button = tk.Button(self.jsluice_control_frame, text="?", command=self.show_jsluice_help, width=2); self.jsluice_help_button.pack(side=tk.LEFT, padx=(0, 2))
        
        # *** Add Raw Output Checkbox ***
        self.jsluice_raw_output_var = tk.IntVar()
        self.jsluice_raw_checkbox = tk.Checkbutton(self.jsluice_control_frame, text="Raw Output", variable=self.jsluice_raw_output_var); self.jsluice_raw_checkbox.pack(side=tk.LEFT, padx=2)
        
        # *** Add Run Button ***
        jsluice_button_state = tk.NORMAL if self.jsluice_path else tk.DISABLED
        self.jsluice_button = tk.Button(self.jsluice_control_frame, text="Run Jsluice", command=self.run_jsluice, fg='black', bg='RoyalBlue1', state=jsluice_button_state); self.jsluice_button.pack(side=tk.LEFT, padx=2)
        
        # (Save buttons remain the same) ...
        self.save_buttons_frame = tk.Frame(self.bottom_button_frame_row1); self.save_buttons_frame.pack(side=tk.RIGHT, fill='x', expand=False, padx=(5, 0))
        self.save_jsluice_button = tk.Button(self.save_buttons_frame, text="Save Jsluice", command=self.save_jsluice_output, fg='black', bg='RoyalBlue1'); self.save_jsluice_button.pack(side=tk.LEFT, padx=2, pady=2)
        self.save_button = tk.Button(self.save_buttons_frame, text="Save Group", command=self.save_iocs, fg='black', bg='seagreen3'); self.save_button.pack(side=tk.LEFT, padx=2, pady=2)
        self.save_folder_button = tk.Button(self.save_buttons_frame, text="Save Individually", command=self.save_iocs_to_folder, fg='black', bg='seagreen3'); self.save_folder_button.pack(side=tk.LEFT, padx=2, pady=2)
        self.save_vt_output_button = tk.Button(self.save_buttons_frame, text="Save VT", command=self.save_vt_output, fg='black', bg='purple1'); self.save_vt_output_button.pack(side=tk.LEFT, padx=2, pady=2)
        
        # ***** END NEW BOTTOM BUTTON LAYOUT *****


    # ***** START Highlighting Methods *****
    def clear_highlight(self):
        """Removes 'highlight' tag from the input text area (used by Find)."""
        self.article_input.tag_remove("highlight", "1.0", tk.END)

    def highlight_text(self):
        """Highlights text in the input area based on the Find entry box."""
        self.clear_highlight()
        find_text = self.find_entry.get()
        if not find_text.strip(): return
        is_regex = bool(self.regex_var.get())
        highlight_tag_name = "highlight"
        try:
            if is_regex: pattern = find_text
            else: pattern = re.escape(find_text)
            start_idx = "1.0"
            while True:
                match_start = self.article_input.search(pattern, start_idx, stopindex=tk.END, regexp=is_regex, nocase=not is_regex)
                if not match_start: break
                if is_regex:
                    search_limit = f"{match_start} + 200 chars"
                    line_text_segment = self.article_input.get(match_start, search_limit)
                    match_obj = re.search(find_text, line_text_segment)
                    if match_obj: match_len = max(1, len(match_obj.group(0))); match_end = f"{match_start}+{match_len}c"
                    else: match_end = f"{match_start}+1c"
                else: match_end = f"{match_start}+{len(find_text)}c"
                self.article_input.tag_add(highlight_tag_name, match_start, match_end)
                start_idx = match_end
        except re.error as e: messagebox.showerror("Invalid Regex", f"Error in Find pattern: {str(e)}")
        except tk.TclError as e: print(f"Warning: Tkinter TclError during Find highlight: {e}"); pass
    # ***** END Highlighting Methods *****

    # ***** Start Copy & Paste Methods *****
    def copy_text(self):
        
        try:
            widget = self.focus_get()
            # Optional: Check if the focused widget is a known text-editable type
            if isinstance(widget, (tk.Text, tk.Entry, scrolledtext.ScrolledText)):
                selected_text = widget.selection_get()
                # selection_get() raises TclError if nothing is selected,
                # so we only proceed if it succeeds and returns text.
                # No explicit check for empty string needed here due to TclError handling.
                self.clipboard_clear()
                self.clipboard_append(selected_text)
            # else: Focused widget is not a type we handle for copy, do nothing.
        except tk.TclError:
            # This handles cases like:
            # - No text selected in the widget
            # - The focused widget doesn't support 'selection_get' (though isinstance helps)
            pass # Silently ignore errors (standard behavior for copy failure)
        except Exception as e:
            # Catch any other unexpected errors
            print(f"Unexpected error during copy: {e}")

    def paste_text(self):
        
        try:
            widget = self.focus_get()
            # Optional: Check if the focused widget is a known text-editable type
            if isinstance(widget, (tk.Text, tk.Entry, scrolledtext.ScrolledText)):
                clipboard_text = self.clipboard_get()
                # clipboard_get() raises TclError if clipboard is empty or inaccessible
                # so we only proceed if it succeeds and returns text.
                # No explicit check for empty string needed here due to TclError handling.

                # Insert text at the cursor (or replacing selected text)
                # Standard insert behavior usually replaces selection if it exists.
                widget.insert(tk.INSERT, clipboard_text)
            # else: Focused widget is not a type we handle for paste, do nothing.
        except tk.TclError:
            # This handles cases like:
            # - Clipboard is empty or cannot be accessed
            # - Focused widget doesn't support 'insert' or 'clipboard_get'
            pass # Silently ignore errors (standard behavior for paste failure)
        except Exception as e:
            # Catch any other unexpected errors
            print(f"Unexpected error during paste: {e}")

    # ***** END Copy & Paste Methods *****

    # ***** START Clearing Methods *****
    def clear_input_text(self):
        if messagebox.askyesno("Confirm Clear", "Are you sure you want to clear the input text?"):
            self.article_input.delete("1.0", tk.END)
            self.article_input.insert(tk.END, "Input Text Here... Use hot keys for copy & paste")
            self.article_input.config(fg='grey')
            self.clear_highlight()
            self.article_input.tag_remove("ioc_highlight", "1.0", tk.END)

    def clear_review_output(self):
        self.review_output.configure(state='normal')
        self.review_output.delete("1.0", tk.END)
        self.review_output.insert(tk.END,"Extracted IOCs will be displayed here... Click Parse IOCs\n\nTo clean up output, I find that getting rid of the following with Find & Replace helps a lot when dealing with Javascript from view page source (etc):\n\t<\n\t>\n\t\'\n\t\"")
        self.review_output.configure(state='disabled')

    def clear_vt_output(self):
        self.vt_results_output.configure(state='normal')
        self.vt_results_output.delete("1.0", tk.END)
        # Re-add instructions
        self.vt_results_output.insert(tk.END, """VirusTotal results will be displayed here...

How to Use VT Buttons:

1. Paste text containing IOCs (IPs, URLs, Hashes) into the input box above.
2. Click **`Parse IOCs`**. Parsed IOCs appear in the 'IOC Review' tab and are highlighted orange in the input box.
3. **In the 'IOC Review' tab**, select (highlight) the IOC(s) you want to check.
    - You can highlight more than one IOC at a time to submit and not have to worry about new lines or byte prefixes.
4. Click the desired **`VT...`** button below.
5. Enter your VT API Key **when prompted** (usually only needed once per session).
6. Results will appear here.""")
        self.vt_results_output.configure(state='disabled')

    def clear_jsluice_output(self):
        """Clears the Jsluice Analysis output area and resets help text."""
        self.jsluice_results_output.configure(state='normal')
        self.jsluice_results_output.delete("1.0", tk.END)
        # Re-insert the initial help text (Important: Must match text in __init__)
        # NOTE: The full help text is quite long, define it once as a class constant
        #       or method for better maintenance if preferred. Using inline here for simplicity.
        jsluice_initial_help_text = """
Usage:
  jsluice <mode> [options] [file...]

Modes:
  urls       Extract URLs and paths
  secrets    Extract secrets and other interesting bits
  tree       Print syntax trees for input files
  query      Run tree-sitter a query against input files
  format     Format JavaScript source using jsbeautifier-go

Global options:
  -c, --concurrency int        Number of files to process concurrently (default 1)
  -C, --cookie string          Cookies to use when making requests to the specified HTTP based arguments
  -H, --header string          Headers to use when making requests to the specified HTTP based arguments (can be specified multiple times)
  -P, --placeholder string     Set the expression placeholder to a custom string (default 'EXPR')
  -j, --raw-input              Read raw JavaScript source from stdin
  -w, --warc                   Treat the input files as WARC (Web ARChive) files
  -i, --no-check-certificate   Ignore validation of server certificates

URLs mode:
  -I, --ignore-strings         Ignore matches from string literals
  -S, --include-source         Include the source code where the URL was found
  -R, --resolve-paths <url>    Resolve relative paths using the absolute URL provided
  -u, --unique                 Only output each URL once per input file

Secrets mode:
  -p, --patterns <file>        JSON file containing user-defined secret patterns to look for

Query mode:
  -q, --query <query>          Tree sitter query to run; e.g. '(string) @matches'
  -r, --raw-output             Do not convert values to native types
  -f, --include-filename       Include the filename in the output
  -F, --format                 Format source code in the output

Examples:
  jsluice urls -C 'auth=true; user=admin;' -H 'Specific-Header-One: true' -H 'Specific-Header-Two: false' local_file.js https://remote.host/example.js
  jsluice query -q '(object) @m' one.js two.js
  find . -name '*.js' | jsluice secrets -c 5 --patterns=apikeys.json
"""
        self.jsluice_results_output.insert(tk.END, jsluice_initial_help_text)
        
        # Add back the warning if jsluice isn't found
        if not self.jsluice_path:
            self.jsluice_results_output.insert(tk.END, "\n\n-------\nWARNING: jsluice command not found or 'python' missing for .py script. 'Run Jsluice' button is disabled.\n-------")
        self.jsluice_results_output.configure(state='disabled')
    # ***** END Clearing Methods *****

    # --- Other Methods ---
    def show_jsluice_help(self):
        help_text = """
Common Jsluice Options (enter in the box):

Mode 'urls':
  -I : Ignore matches from string literals
  -S : Include source code where URL was found
  -R <url> : Resolve relative paths using base URL

Mode 'secrets':
  -p <file> : JSON file with custom patterns

Mode 'query':
  -q <query> : Tree-sitter query (e.g., '(string) @m')
  -r : Raw query output (don't JSON-encode)

(Refer to jsluice documentation for all options) https://github.com/BishopFox/jsluice
        """
        messagebox.showinfo("Jsluice Options Help", help_text)

    def on_input_focus_in(self, event):
         if self.article_input.get("1.0", "end-1c") == "Input Text Here... Use hot keys for copy & paste":
            self.article_input.delete("1.0", tk.END)
            self.article_input.config(fg='black')

    def on_input_focus_out(self, event):
        if not self.article_input.get("1.0", "end-1c"):
            self.article_input.insert(tk.END, "Input Text Here... Use hot keys for copy & paste")
            self.article_input.config(fg='grey')

    def find_and_replace(self):
        find_str = self.find_entry.get()
        replace_str = self.replace_entry.get()
        input_text_widget = self.article_input
        is_regex = self.regex_var.get() == 1
        if not find_str: messagebox.showwarning("Missing Input", "Please enter text to find."); return
        count = 0
        try:
            if is_regex:
                current_content = input_text_widget.get("1.0", tk.END)
                new_content, count = re.subn(find_str, replace_str, current_content)
                if count > 0:
                    input_text_widget.delete("1.0", tk.END); input_text_widget.insert("1.0", new_content)
                    self.clear_highlight(); self.article_input.tag_remove("ioc_highlight", "1.0", tk.END)
            else:
                start_index = "1.0"
                while True:
                    pos = input_text_widget.search(find_str, start_index, stopindex=tk.END, nocase=True)
                    if not pos: break
                    end_pos = f"{pos}+{len(find_str)}c"; input_text_widget.delete(pos, end_pos); input_text_widget.insert(pos, replace_str); count += 1
                    start_index = f"{pos}+{len(replace_str)}c"
            if count > 0: messagebox.showinfo("Replace Complete", f"Made {count} replacements.")
            else: messagebox.showinfo("Replace Complete", "No occurrences found to replace.")
        except re.error as e: messagebox.showerror("Regex Error", f"Invalid Regex for replacement:\n{e}")
        except tk.TclError as e: messagebox.showerror("Replace Error", f"A Tkinter error occurred: {e}")
        except Exception as e: messagebox.showerror("Error", f"An unexpected error occurred during replace: {e}")

    def save_input_text(self):
        text_to_save = self.article_input.get("1.0", tk.END)
        if not text_to_save.strip() or text_to_save.strip() == "Input Text Here... Use hot keys for copy & paste": messagebox.showwarning("Empty Input", "There is no input text to save."); return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")], title="Save Input Text As")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f: f.write(text_to_save)
                messagebox.showinfo("Success", f"Input text saved to:\n{file_path}")
            except Exception as e: messagebox.showerror("Save Error", f"Failed to save input text:\n{e}")

    def parse_iocs(self):
        input_text = self.article_input.get("1.0", tk.END)
        if not input_text or input_text.strip() == "Input Text Here... Use hot keys for copy & paste": messagebox.showwarning("Input Missing", "Please provide text in the input box first."); return
        self.article_input.tag_remove("ioc_highlight", "1.0", tk.END)
        self.found_iocs = {}
        self.review_output.configure(state='normal'); self.review_output.delete("1.0", tk.END)
        total_unique_found = 0
        for name, regex_pattern in regexes.items():
            unique_matches_for_category = set()
            try:
                if not hasattr(regex_pattern, 'finditer'): raise TypeError(f"'{name}' is not a compiled regex pattern.")
                for match in regex_pattern.finditer(input_text):
                    match_string = match.group(0).strip()
                    if match_string:
                        unique_matches_for_category.add(match_string)
                        start_index = f"1.0 + {match.start()} chars"; end_index = f"1.0 + {match.end()} chars"
                        try: self.article_input.tag_add("ioc_highlight", start_index, end_index)
                        except tk.TclError as tag_error: print(f"Warning: TclError applying tag '{name}' at {start_index}-{end_index}: {tag_error}")
                if unique_matches_for_category:
                    sorted_matches = sorted(list(unique_matches_for_category))
                    self.found_iocs[name] = sorted_matches
                    self.review_output.insert(tk.END, f"--- {name} ---\n", "bold")
                    for ioc in sorted_matches: self.review_output.insert(tk.END, ioc + "\n")
                    self.review_output.insert(tk.END, "\n"); total_unique_found += len(sorted_matches)
            except re.error as compile_error: print(f"Error processing regex '{name}': Invalid pattern - {compile_error}"); self.review_output.insert(tk.END, f"--- Error in pattern {name}: {compile_error} ---\n\n", ("error"))
            except Exception as e: print(f"Error processing regex '{name}': {e}"); self.review_output.insert(tk.END, f"--- Error processing {name}: {e} ---\n\n", ("error"))
        if total_unique_found == 0: self.review_output.insert(tk.END, "No IOCs found matching the defined patterns.")
        self.review_output.configure(state='disabled')

    def defang_iocs(self):
        self.review_output.configure(state='normal'); current_text = self.review_output.get("1.0", tk.END); self.review_output.configure(state='disabled')
        if not current_text.strip() or current_text.strip().startswith("Extracted IOCs"): messagebox.showwarning("No IOCs", "No IOCs extracted to defang. Parse first."); return
        defanged_text = current_text.replace('.', '[.]').replace('http', 'hxxp').replace('ftp', 'fxp')
        self.review_output.configure(state='normal'); self.review_output.delete("1.0", tk.END); self.review_output.insert("1.0", defanged_text); self.review_output.configure(state='disabled')
        messagebox.showinfo("Defanged", "IOCs in the review box have been defanged.")

    def refang_iocs(self):
        self.review_output.configure(state='normal'); current_text = self.review_output.get("1.0", tk.END); self.review_output.configure(state='disabled')
        if not current_text.strip() or current_text.strip().startswith("Extracted IOCs"): messagebox.showwarning("No IOCs", "No IOCs extracted to refang. Parse first."); return
        refanged_text = current_text.replace('[.]', '.').replace('hxxp', 'http').replace('fxp', 'ftp')
        self.review_output.configure(state='normal'); self.review_output.delete("1.0", tk.END); self.review_output.insert("1.0", refanged_text); self.review_output.configure(state='disabled')
        messagebox.showinfo("Refanged", "IOCs in the review box have been refanged.")

    # --- Save Methods ---
    def save_iocs(self):
        is_disabled = self.review_output['state'] == 'disabled';
        if is_disabled: self.review_output.configure(state='normal')
        text_to_save = self.review_output.get("1.0", "end-1c");
        if is_disabled: self.review_output.configure(state='disabled')
        if not text_to_save.strip() or text_to_save.strip().startswith("Extracted IOCs"): messagebox.showwarning("No IOCs", "No IOCs to save.\nPlease parse text first."); return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")], title="Save Extracted IOCs As Group")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f: f.write(text_to_save)
                messagebox.showinfo("Success", f"IOCs saved to:\n{file_path}")
            except Exception as e: messagebox.showerror("Save Error", f"Failed to save IOCs:\n{e}")

    def save_iocs_to_folder(self):
        if not self.found_iocs: messagebox.showwarning("No IOCs", "No parsed IOCs found to save individually. Please parse text first."); return
        folder = filedialog.askdirectory(title="Select Folder to Save IOC Categories");
        if not folder: return
        saved, errors = 0, []
        cats = self.found_iocs
        for category, iocs in cats.items():
            if not iocs: continue
            safe_filename = "".join(x for x in category if x.isalnum() or x in (' ', '_', '-')).rstrip(); safe_filename = re.sub(r'\s+', '_', safe_filename)
            if not safe_filename: safe_filename = "unknown_category"
            fpath = os.path.join(folder, f"{safe_filename}.txt")
            try:
                with open(fpath, 'w', encoding='utf-8') as f: f.write("\n".join(iocs) + "\n"); saved += 1
            except Exception as e: errors.append(f"Failed to save '{category}': {e}")
        if errors: messagebox.showerror("Save Errors", f"Successfully saved {saved} categories.\nErrors occurred for:\n" + "\n".join(errors))
        elif saved: messagebox.showinfo("Success", f"Saved {saved} IOC categories to folder:\n{folder}")
        else: messagebox.showwarning("No Data", "No valid IOC data found to save.")

    def save_vt_output(self):
        is_disabled = self.vt_results_output['state'] == 'disabled'
        if is_disabled: self.vt_results_output.configure(state='normal')
        text = self.vt_results_output.get("1.0", "end-1c")
        if is_disabled: self.vt_results_output.configure(state='disabled')
        if not text.strip() or text.strip().startswith("VirusTotal results"): messagebox.showwarning("No VT Results", "Nothing to save."); return
        fpath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("TXT", "*.txt"), ("All", "*.*")], title="Save VT Output As")
        if fpath:
            try:
                with open(fpath, 'w', encoding='utf-8') as f: f.write(text)
                messagebox.showinfo("Success", f"VT output saved to:\n{fpath}")
            except Exception as e: messagebox.showerror("Save Error", f"Failed to save VT output:\n{e}")

    def save_jsluice_output(self):
        is_disabled = self.jsluice_results_output['state'] == 'disabled';
        if is_disabled: self.jsluice_results_output.configure(state='normal')
        text_to_save = self.jsluice_results_output.get("1.0", "end-1c").strip();
        if is_disabled: self.jsluice_results_output.configure(state='disabled')
        initial_help_stripped = self.jsluice_initial_help_text.strip(); warning_text_part = "WARNING: jsluice command not found"
        is_empty = not text_to_save; is_only_help = text_to_save == initial_help_stripped
        is_only_help_with_warning = (text_to_save.startswith("Usage:") and warning_text_part in text_to_save and len(text_to_save) < len(self.jsluice_initial_help_text) + 150)
        if is_empty or is_only_help or is_only_help_with_warning: messagebox.showwarning("No Jsluice Results", "No actual Jsluice analysis results to save."); return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("JSON Lines", "*.jsonl"), ("All Files", "*.*")], title="Save Jsluice Output As")
        if file_path:
            try:
                if not text_to_save.endswith('\n'): text_to_save += '\n'
                with open(file_path, 'w', encoding='utf-8') as f: f.write(text_to_save)
                messagebox.showinfo("Success", f"Jsluice output saved to:\n{file_path}")
            except Exception as e: messagebox.showerror("Save Error", f"Failed to save Jsluice output:\n{e}")

# ***** START NEW VT Methods *****
    # + Helper function for getting selection from active tab
    def _get_text_selection_from_active_tab(self):
        """Gets selected text from IOC Review or Jsluice tabs."""
        try:
            selected_tab_widget = self.output_notebook.select()
            if not selected_tab_widget:
                return None, "No tab selected." # Should not happen

            # Find the widget associated with the selected tab ID
            # This relies on the tab order: 0=Review, 1=VT, 2=Jsluice
            tab_index = self.output_notebook.index(selected_tab_widget)

            target_widget = None
            source_tab_name = None
            if tab_index == 0: # IOC Review Tab
                target_widget = self.review_output
                source_tab_name = "IOC Review"
            elif tab_index == 2: # Jsluice Analysis Tab
                target_widget = self.jsluice_results_output
                source_tab_name = "Jsluice Analysis"
            else: # VT Results or other tab selected
                return None, "Please select text in the 'IOC Review' or 'Jsluice Analysis' tab."

            # Enable widget temporarily if needed to get selection
            original_state = target_widget['state']
            selected_text = None
            error_msg = "Please select text in the active tab first." # Default error
            try:
                if original_state == 'disabled':
                    target_widget.configure(state='normal')
                # Get selection - this raises TclError if no selection
                selected_text = target_widget.get(tk.SEL_FIRST, tk.SEL_LAST)
            except tk.TclError:
                # Keep default error message
                pass
            finally:
                # Restore original state
                if original_state == 'disabled':
                    target_widget.configure(state='disabled')

            if selected_text:
                 return selected_text, source_tab_name # Return text and source tab name
            else:
                 return None, error_msg # Return None and specific error

        except Exception as e:
             # Catch potential errors like notebook not having tabs yet etc.
             return None, f"Error getting selection: {e}"

    # ***** START NEW VT Methods *****
    # + Helper function for getting selection from active tab
    def _get_text_selection_from_active_tab(self):
        """Gets selected text from IOC Review or Jsluice tabs."""
        try:
            selected_tab_widget = self.output_notebook.select()
            if not selected_tab_widget:
                return None, "No tab selected." # Should not happen

            # Find the widget associated with the selected tab ID
            # This relies on the tab order: 0=Review, 1=VT, 2=Jsluice
            tab_index = self.output_notebook.index(selected_tab_widget)

            target_widget = None
            source_tab_name = None
            if tab_index == 0: # IOC Review Tab
                target_widget = self.review_output
                source_tab_name = "IOC Review"
            elif tab_index == 2: # Jsluice Analysis Tab
                target_widget = self.jsluice_results_output
                source_tab_name = "Jsluice Analysis"
            else: # VT Results or other tab selected
                return None, "Please select text in the 'IOC Review' or 'Jsluice Analysis' tab."

            # Enable widget temporarily if needed to get selection
            original_state = target_widget['state']
            selected_text = None
            error_msg = "Please select text in the active tab first." # Default error
            try:
                if original_state == 'disabled':
                    target_widget.configure(state='normal')
                # Get selection - this raises TclError if no selection
                selected_text = target_widget.get(tk.SEL_FIRST, tk.SEL_LAST)
            except tk.TclError:
                # Keep default error message
                pass
            finally:
                # Restore original state
                if original_state == 'disabled':
                    target_widget.configure(state='disabled')

            if selected_text:
                 return selected_text, source_tab_name # Return text and source tab name
            else:
                 return None, error_msg # Return None and specific error

        except Exception as e:
             # Catch potential errors like notebook not having tabs yet etc.
             return None, f"Error getting selection: {e}"


    def get_vt_api_key(self):
       """Prompts for VT API key if not already stored. Strips input."""
       if not self.vt_api_key:
           key = simpledialog.askstring("API Key Required", "Enter your VirusTotal API Key:", show='*')
           if key:
               self.vt_api_key = key.strip() # *** STRIP the key ***
               if not self.vt_api_key:
                    messagebox.showerror("API Key Missing", "Entered API Key was empty.")
                    return None
           else:
               messagebox.showerror("API Key Missing", "VT API Key is required.")
               return None
       return self.vt_api_key

    def is_url(self, string_to_check):
        """Checks if a string starts with http:// or https:// (Corrected)."""
        if not isinstance(string_to_check, str): return False
        return string_to_check.startswith("http://") or string_to_check.startswith("https://")

    def query_virustotal(self, ioc):
        if not self.vt_api_key: return "Error: VT API Key not available."
        headers = { "Accept": "application/json", "x-apikey": self.vt_api_key }
        report_link = "N/A"; api_url = None; ioc_type = "Unknown"
        if self.is_url(ioc):
            try: encoded_url = base64.urlsafe_b64encode(ioc.encode()).decode().strip("="); api_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"; report_link = f"https://www.virustotal.com/gui/url/{encoded_url}/detection"; ioc_type = "URL"
            except Exception as e: return f"Error encoding URL {ioc}: {e}"
        elif len(ioc) in (32, 40, 64) and all(c in '0123456789abcdefABCDEF' for c in ioc): api_url = f"https://www.virustotal.com/api/v3/files/{ioc}"; report_link = f"https://www.virustotal.com/gui/file/{ioc}/detection"; ioc_type = "Hash"
        else: return f"IOC type not recognized/supported for query: {ioc}"
        try:
            response = requests.get(api_url, headers=headers, timeout=20)
            if response.status_code == 200:
                 data = response.json();
                 if 'data' in data and 'attributes' in data['data']:
                    attributes = data['data']['attributes']; stats = attributes.get('last_analysis_stats', {}); malicious = stats.get('malicious', 0); suspicious = stats.get('suspicious', 0); harmless = stats.get('harmless', 0); undetected = stats.get('undetected', 0); total_vendors = malicious + suspicious + harmless + undetected
                    last_analysis_date_ts = attributes.get("last_analysis_date"); readable_date = "N/A"
                    if last_analysis_date_ts:
                         try: readable_date = datetime.utcfromtimestamp(last_analysis_date_ts).strftime('%Y-%m-%d %H:%M:%S UTC')
                         except ValueError: readable_date = "Invalid Date"
                    result_str = (f"Score: {malicious}/{total_vendors} malicious\n" f"Last Analysis: {readable_date}\n" f"Link: {report_link}"); return result_str
                 else: return f"Error: Unexpected data structure in VT response for {ioc}"
            elif response.status_code == 404: return f"{ioc_type} not found on VirusTotal."
            else:
                 try: error_message = response.json().get('error', {}).get('message', f"HTTP Status {response.status_code}")
                 except ValueError: error_message = f"HTTP Status {response.status_code} - {response.text[:100]}"
                 return f"Error querying VirusTotal for {ioc}: {error_message}"
        except requests.exceptions.RequestException as e: return f"Network Error querying VirusTotal for {ioc}: {e}"
        except Exception as e: return f"Unexpected Error querying VT for {ioc}: {e}"

    def on_vt_button_click(self):
        """Handles 'VT Check Selected' button. Queries selected IOCs from active tab."""
        if not self.get_vt_api_key(): return
        selected_text, error_msg = self._get_text_selection_from_active_tab() # Use helper
        if selected_text is None:
            messagebox.showwarning("Selection Error", error_msg) # Show specific error
            return

        iocs = selected_text.splitlines()
        if not iocs or not any(ioc.strip() for ioc in iocs):
             messagebox.showwarning("Selection Error", "No valid IOCs selected.")
             return

        self.vt_results_output.configure(state='normal'); self.vt_results_output.delete(1.0, tk.END)
        results_to_display = []
        for ioc in iocs:
            ioc = ioc.strip()
            if ioc:
                result = self.query_virustotal(ioc)
                results_to_display.append((ioc, result))
        if results_to_display:
            for ioc, result in results_to_display:
                self.vt_results_output.insert(tk.END, ioc + ":\n", "bold")
                self.vt_results_output.insert(tk.END, result + "\n\n")
        else: self.vt_results_output.insert(tk.END, "No results generated.")
        self.vt_results_output.configure(state='disable')

    def submit_url_for_analysis(self):
        """Handles 'VT Submit URL(s)'. Submits selected URLs from active tab."""
        if not self.get_vt_api_key(): return
        selected_text, error_msg = self._get_text_selection_from_active_tab() # Use helper
        if selected_text is None:
            messagebox.showwarning("Selection Error", error_msg)
            return

        urls = selected_text.splitlines()
        if not urls or not any(url.strip() for url in urls):
             messagebox.showwarning("Selection Error", "No valid URLs selected.")
             return

        self.vt_results_output.configure(state='normal'); self.vt_results_output.delete(1.0, tk.END)
        headers = { "Accept": "application/json", "x-apikey": self.vt_api_key }
        submit_url_endpoint = "https://www.virustotal.com/api/v3/urls"

        for url in urls:
            url = url.strip()
            if url and self.is_url(url):
                data = {"url": url}
                try:
                    response = requests.post(submit_url_endpoint, headers=headers, data=data, timeout=20)
                    self.vt_results_output.insert(tk.END, f"URL {url}:\n", "bold")
                    if response.status_code == 200:
                        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                        analysis_url = f"https://www.virustotal.com/gui/url/{encoded_url}/detection"
                        self.vt_results_output.insert(tk.END, f"Submitted/Queued successfully.\nCheck Report: {analysis_url}\n\n")
                    else:
                        try: error_message = response.json().get('error', {}).get('message', f'HTTP {response.status_code}')
                        except ValueError: error_message = f'HTTP {response.status_code} - {response.text[:100]}'
                        self.vt_results_output.insert(tk.END, f"Error submitting for analysis: {error_message}\n\n", ("error"))
                except requests.exceptions.RequestException as e: self.vt_results_output.insert(tk.END, f"Network Error submitting: {e}\n\n", ("error"))
                except Exception as e: self.vt_results_output.insert(tk.END, f"Unexpected Error submitting: {e}\n\n", ("error"))
            elif url: self.vt_results_output.insert(tk.END, f"Skipping non-URL: {url}\n\n", ("error"))
        self.vt_results_output.configure(state='disable')

    def get_hash_details(self, hash_value):
        if not self.vt_api_key: return {"error": "API Key not available"}
        headers = { "Accept": "application/json", "x-apikey": self.vt_api_key }
        file_info_endpoint = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        try:
            response = requests.get(file_info_endpoint, headers=headers, timeout=20)
            if response.status_code == 200:
                attributes = response.json().get("data", {}).get("attributes", {})
                return { "md5": attributes.get("md5", "N/A"), "sha1": attributes.get("sha1", "N/A"), "sha256": attributes.get("sha256", "N/A") }
            elif response.status_code == 404: return {"error": "Hash not found on VirusTotal."}
            else:
                try: error_message = response.json().get('error', {}).get('message', f'HTTP {response.status_code}')
                except ValueError: error_message = f'HTTP {response.status_code} - {response.text[:100]}'
                return {"error": error_message}
        except requests.exceptions.RequestException as e: return {"error": f"Network Error getting hash details: {e}"}
        except Exception as e: return {"error": f"Unexpected Error getting hash details: {e}"}

    def get_all_hash_details(self):
         """Handles 'VT Get Hash Details'. Fetches details for selected hashes from active tab."""
         if not self.get_vt_api_key(): return
         selected_text, error_msg = self._get_text_selection_from_active_tab() # Use helper
         if selected_text is None:
            messagebox.showwarning("Selection Error", error_msg)
            return

         hashes = selected_text.splitlines()
         if not hashes or not any(h.strip() for h in hashes):
             messagebox.showwarning("Selection Error", "No valid Hashes selected.")
             return

         self.vt_results_output.configure(state='normal'); self.vt_results_output.delete(1.0, tk.END)
         for hash_val in hashes:
            hash_val = hash_val.strip()
            if hash_val and len(hash_val) in (32, 40, 64) and all(c in '0123456789abcdefABCDEF' for c in hash_val):
                hash_details = self.get_hash_details(hash_val)
                self.vt_results_output.insert(tk.END, f"Input Hash: {hash_val}\n", "bold")
                if "error" not in hash_details:
                    self.vt_results_output.insert(tk.END, f"  MD5:    {hash_details.get('md5', 'N/A')}\n")
                    self.vt_results_output.insert(tk.END, f"  SHA-1:  {hash_details.get('sha1', 'N/A')}\n")
                    self.vt_results_output.insert(tk.END, f"  SHA-256:{hash_details.get('sha256', 'N/A')}\n\n")
                else: self.vt_results_output.insert(tk.END, f"  Error: {hash_details['error']}\n\n", ("error"))
            elif hash_val: self.vt_results_output.insert(tk.END, f"Skipping invalid hash format: {hash_val}\n\n", ("error"))
         self.vt_results_output.configure(state='disable')

    def get_mitre_ttp_details(self, hash_value):
        if not self.vt_api_key: return {"error": "API Key not available"}
        headers = { "Accept": "application/json", "x-apikey": self.vt_api_key }
        ttp_info_endpoint = f"https://www.virustotal.com/api/v3/files/{hash_value}/behaviour_mitre_trees"
        try:
            response = requests.get(ttp_info_endpoint, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json(); all_ttps = {}
                sandboxes_data = data.get("data", {})
                if not sandboxes_data: return {"error": "No MITRE behaviour data found."}
                for sandbox_name, sandbox_results in sandboxes_data.items():
                    for tactic in sandbox_results.get("tactics", []):
                        tactic_name = tactic.get("name", "Unknown Tactic")
                        for technique in tactic.get("techniques", []):
                            tech_id = technique.get("id"); tech_name = technique.get("name", "Unknown Technique"); tech_link = technique.get("link", "")
                            if tech_id:
                                if tech_id not in all_ttps: all_ttps[tech_id] = {"name": tech_name, "link": tech_link, "tactics": set()}
                                all_ttps[tech_id]["tactics"].add(tactic_name)
                if not all_ttps: return {"error": "No specific MITRE Techniques extracted."}
                ttp_list = [{"id": tech_id, "name": d["name"], "link": d["link"], "tactics": sorted(list(d["tactics"]))} for tech_id, d in sorted(all_ttps.items())]
                return ttp_list
            elif response.status_code == 404: return {"error": "Hash not found / no behaviour report."}
            else:
                try: error_message = response.json().get('error', {}).get('message', f'HTTP {response.status_code}')
                except ValueError: error_message = f'HTTP {response.status_code} - {response.text[:100]}'
                return {"error": error_message}
        except requests.exceptions.RequestException as e: return {"error": f"Network Error getting TTP details: {e}"}
        except Exception as e: return {"error": f"Unexpected Error getting TTP details: {e}"}

    def submit_for_mitre_ttps(self):
        """Handles 'Get MITRE TTPs'. Fetches TTPs for selected hashes from active tab."""
        if not self.get_vt_api_key(): return
        selected_text, error_msg = self._get_text_selection_from_active_tab() # Use helper
        if selected_text is None:
            messagebox.showwarning("Selection Error", error_msg)
            return

        hashes = selected_text.splitlines()
        if not hashes or not any(h.strip() for h in hashes):
             messagebox.showwarning("Selection Error", "No valid Hashes selected.")
             return

        self.vt_results_output.configure(state='normal'); self.vt_results_output.delete(1.0, tk.END)
        for hash_val in hashes:
            hash_val = hash_val.strip()
            if hash_val and len(hash_val) in (32, 40, 64) and all(c in '0123456789abcdefABCDEF' for c in hash_val):
                ttp_details = self.get_mitre_ttp_details(hash_val)
                self.vt_results_output.insert(tk.END, f"Hash: {hash_val}\n", "bold")
                if isinstance(ttp_details, list):
                    if ttp_details:
                        for ttp in ttp_details:
                            self.vt_results_output.insert(tk.END, f"  {ttp['id']}: {ttp['name']}\n")
                            self.vt_results_output.insert(tk.END, f"    Tactics: {', '.join(ttp['tactics'])}\n")
                            self.vt_results_output.insert(tk.END, f"    Link: {ttp['link']}\n") # Link optional
                        self.vt_results_output.insert(tk.END, "\n")
                    else: self.vt_results_output.insert(tk.END, "  No specific MITRE Techniques extracted.\n\n")
                elif isinstance(ttp_details, dict) and "error" in ttp_details: self.vt_results_output.insert(tk.END, f"  Error: {ttp_details['error']}\n\n", ("error"))
                else: self.vt_results_output.insert(tk.END, "  Unexpected error retrieving TTP data.\n\n", ("error"))
            elif hash_val: self.vt_results_output.insert(tk.END, f"Skipping invalid hash format for TTPs: {hash_val}\n\n", ("error"))
        self.vt_results_output.configure(state='disable')
    # ***** END NEW VT Methods *****


    def run_jsluice(self):
        """Runs jsluice using a timestamped temporary file and formats the output."""
        if not self.jsluice_path:
            messagebox.showerror("Jsluice Error", "jsluice command not found...")
            return  
        input_text = self.article_input.get("1.0", tk.END).strip()
        if not input_text or input_text == "Input Text Here... Use hot keys for copy & paste":
            messagebox.showwarning("Input Missing", "Provide text for jsluice.")
            return  
        selected_mode = self.jsluice_mode_combobox.get()
        if not selected_mode:
            messagebox.showerror("Jsluice Error", "Please select a jsluice mode.")
            return  
        custom_options_str = self.jsluice_options_entry.get().strip()
        additional_args = []
        if custom_options_str:
            try:
                additional_args = shlex.split(custom_options_str) 
            except ValueError as e:
                messagebox.showerror("Jsluice Options Error", f"Error parsing options: {e}")
                return 
        jsluice_command_args = [selected_mode] + additional_args
        show_raw = bool(self.jsluice_raw_output_var.get()) 

        self.jsluice_results_output.configure(state='normal') 
        self.jsluice_results_output.delete("1.0", tk.END)
        self.update_idletasks()

        temp_input_filepath = None # Initialize here
        process_info_inserted = False # Flag to track if path was displayed

        try:
            # === START: Modified File Creation ===
            try:
                temp_dir = tempfile.gettempdir() # Get system temp directory
                now = datetime.now() # Get current time 
                timestamp = now.strftime("%Y%m%d_%H%M%S") # Format timestamp
                # Define filename components
                prefix = "jsluice_input_"
                suffix = ".js"
                # Construct the full path
                temp_input_filepath = os.path.join(temp_dir, f"{prefix}{timestamp}{suffix}")

                # Write the input text to the timestamped file
                with open(temp_input_filepath, 'w', encoding='utf-8') as f:
                    f.write(input_text)

            except Exception as file_error:
                 messagebox.showerror("File Error", f"Failed to create temporary input file:\n{file_error}")
                 # Set state back in finally block if needed
                 return # Stop execution if file creation fails
            # === END: Modified File Creation ===

            # --- Insert file path info EARLY ---
            if temp_input_filepath:
                self.jsluice_results_output.insert(tk.END, f"--- Input saved to temporary file: {temp_input_filepath} ---\n\n", ("bold"))
                process_info_inserted = True
                self.update_idletasks() # Ensure it shows up immediately

            # Run the subprocess using the new timestamped file path
            final_command = self.jsluice_base_command + jsluice_command_args + [temp_input_filepath] 
            # final_command_display = ' '.join(shlex.quote(arg) for arg in final_command) # Displaying command is optional
            process = subprocess.run(final_command, capture_output=True, text=True, encoding='utf-8', errors='replace') 

            # Process and display output 
            if process.returncode == 0: 
                self.jsluice_results_output.insert(tk.END, f"--- Jsluice Results ({selected_mode} mode) ---\n\n", ("bold"))
                if not process.stdout.strip():
                    self.jsluice_results_output.insert(tk.END, "(No output produced by jsluice)\n")
                elif show_raw: 
                     self.jsluice_results_output.insert(tk.END, process.stdout) # Display raw output
                else:
                    # --- Try Formatted Output ---
                    lines = process.stdout.strip().splitlines() 
                    categorized_results = {} 
                    unparsed_lines = [] 
                    parsed_json = False 
                    for line in lines:
                        kind = None 
                        match = None 
                        category = None
                        value_to_display = None
                        try:
                            data = json.loads(line) 
                            parsed_json = True 
                            
                            if selected_mode == 'urls':
                                url = data.get('url') 
                                if url: category = "URLs"; value_to_display = url
                            elif selected_mode == 'secrets':
                                kind = data.get('kind') 
                                match = data.get('match') 
                                if kind and match: category = "Secrets"; value_to_display = f"{kind}: {match}" 
                            elif selected_mode == 'query': category = "Query Results"; value_to_display = json.dumps(data) 

                            if category is None: category = "Other JSON Data"; value_to_display = json.dumps(data) 

                            if value_to_display is not None:
                                category_set = categorized_results.setdefault(category, set()) 
                                category_set.add(value_to_display)
                        except json.JSONDecodeError: 
                            if line.strip(): unparsed_lines.append(line)
                    # --- Display Formatted Results ---
                    if categorized_results: 
                        for category, item_set in sorted(categorized_results.items()):
                            self.jsluice_results_output.insert(tk.END, f"--- {category} ---\n", ("bold"))
                            for item in sorted(list(item_set)):
                                self.jsluice_results_output.insert(tk.END, item + "\n")
                            self.jsluice_results_output.insert(tk.END, "\n") 
                    elif not parsed_json and process.stdout.strip(): # Fallback to raw if no JSON parsed 
                        mode_display_name = selected_mode.capitalize()
                        self.jsluice_results_output.insert(tk.END, f"--- Raw Output ({mode_display_name} Mode) ---\n", ("bold"))
                        self.jsluice_results_output.insert(tk.END, process.stdout + "\n\n")
                    if parsed_json and unparsed_lines: # 
                        self.jsluice_results_output.insert(tk.END, "--- Unparsed Lines / Non-JSON Data ---\n", ("bold", "error"))
                        self.jsluice_results_output.insert(tk.END, "\n".join(unparsed_lines) + "\n")
            else: # Handle non-zero return code errors 
                self.jsluice_results_output.insert(tk.END, f"--- Jsluice Error (Exit Code: {process.returncode}) ---\n", ("error", "bold"))
                if process.stderr:
                    self.jsluice_results_output.insert(tk.END, process.stderr + "\n", ("error"))
                else:
                    self.jsluice_results_output.insert(tk.END, "(No error message on stderr)\n", ("error"))
                if process.stdout: # Show stdout even on error if it exists 
                    self.jsluice_results_output.insert(tk.END, "--- Stdout Received Before Error ---\n", ("bold"))
                    self.jsluice_results_output.insert(tk.END, process.stdout + "\n")

        except FileNotFoundError: 
             # Handle command not found error
             # Display path if created
             if temp_input_filepath and not process_info_inserted:
                 self.jsluice_results_output.insert(tk.END, f"--- Input file created: {temp_input_filepath} ---\n", ("bold"))
                 process_info_inserted = True # Mark as inserted
             # Add specific error message about command not found
             cmd_name = self.jsluice_base_command[0] if self.jsluice_base_command else "jsluice"
             self.jsluice_results_output.insert(tk.END, f"--- Error: Command '{cmd_name}' not found ---\n", ("error", "bold"))

        except Exception as e: 
             # Handle other Python errors during execution
             # Display path if created
             if temp_input_filepath and not process_info_inserted:
                 self.jsluice_results_output.insert(tk.END, f"--- Input file created: {temp_input_filepath} ---\n", ("bold"))
                 process_info_inserted = True # Mark as inserted
             self.jsluice_results_output.insert(tk.END, f"--- Python Error During Jsluice Execution ---\n{type(e).__name__}: {e}", ("error", "bold"))
             import traceback
             self.jsluice_results_output.insert(tk.END, f"\n{traceback.format_exc()}", ("error")) 

        finally:
            # === File cleanup (os.unlink) is intentionally removed ===
            # if temp_input_filepath and os.path.exists(temp_input_filepath):
            #     try:
            #         # os.unlink(temp_input_filepath) # NO LONGER DELETING
            #     except Exception as unlink_e:
            #         print(f"Warning: Failed to delete temp file {temp_input_filepath}: {unlink_e}")

            # Ensure path displayed if somehow missed (optional safe check)
            if temp_input_filepath and not process_info_inserted:
                 self.jsluice_results_output.insert(tk.END, f"--- Input saved to temporary file: {temp_input_filepath} ---\n", ("bold"))

            self.jsluice_results_output.configure(state='disabled')

# *** NEW Jsluice CLI Method ***
    def run_shell_command_event(self, event=None):
        """Wrapper to call run_shell_command from Enter key."""
        self.run_shell_command()

    def run_shell_command(self):
        """Runs a command using the system shell with a timeout."""

        # Define a timeout in seconds
        COMMAND_TIMEOUT = 30 # e.g., 30 seconds

        # ***  Get command from the CORRECT entry widget ***
        command_str = self.shell_command_entry.get().strip()
        if not command_str:
            messagebox.showwarning("Input Missing", "Please enter a shell command.")
            return

        # *** Prepare the CORRECT output area ***
        self.shell_command_output.configure(state='normal')
        self.shell_command_output.delete("1.0", tk.END)
        self.shell_command_output.insert(tk.END, f"Running (Timeout={COMMAND_TIMEOUT}s): {command_str}\n\n", ("bold")) # Show timeout
        self.update_idletasks()

        process = None # Initialize process to None
        try:
            process = subprocess.Popen(
                command_str,   # Pass the command as a single string
                shell=True,    # Use the shell to interpret the command
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,     # Decode stdout/stderr as text
                encoding='utf-8', errors='replace',
            )

            # Add try...except for TimeoutExpired
            try:
                # Wait for completion with timeout
                stdout, stderr = process.communicate(timeout=COMMAND_TIMEOUT)
                return_code = process.returncode

            except subprocess.TimeoutExpired:
                 # ***  Use CORRECT output widget ***
                self.shell_command_output.insert(tk.END, f"\n--- Command Timed Out (>{COMMAND_TIMEOUT}s) ---\n", ("error", "bold"))
                self.shell_command_output.insert(tk.END, "Attempting to terminate process...\n", ("error"))
                process.kill() # Kill the timed-out process

                # Try to communicate again quickly after killing
                try:
                    stdout, stderr = process.communicate(timeout=1) # Short timeout for cleanup
                except Exception as post_kill_e:
                    stderr = (stderr or "") + f"\nError gathering output after kill: {post_kill_e}"

                return_code = process.returncode # Will likely be a termination signal code
                 # ***  Use CORRECT output widget ***
                self.shell_command_output.insert(tk.END, f"Process terminated.\n", ("error"))


            # ***  Display results in CORRECT output widget ***
            if stdout:
                self.shell_command_output.insert(tk.END, "--- stdout ---\n", ("bold"))
                self.shell_command_output.insert(tk.END, stdout + "\n")
            if stderr:
                self.shell_command_output.insert(tk.END, "--- stderr ---\n", ("bold", "error"))
                self.shell_command_output.insert(tk.END, stderr + "\n", ("error"))

            exit_code_tag = ("error") if return_code != 0 else ()
             # ***  Use CORRECT output widget ***
            self.shell_command_output.insert(tk.END, f"\n--- Process finished (Exit Code: {return_code}) ---\n", ("bold",) + exit_code_tag)

        except Exception as e:
             # General error handling
             # ***  Use CORRECT output widget ***
             self.shell_command_output.insert(tk.END, f"--- Python Error During Shell Execution ---\n{type(e).__name__}: {e}", ("error", "bold"))
             import traceback
              # ***  Use CORRECT output widget ***
             self.shell_command_output.insert(tk.END, f"\n{traceback.format_exc()}", ("error"))
             # Ensure process is killed if Popen succeeded but another error occurred
             if process and process.poll() is None:
                 try:
                     process.kill()
                      # ***  Use CORRECT output widget ***
                     self.shell_command_output.insert(tk.END, f"\nProcess killed due to error.\n", ("error"))
                 except Exception as kill_err:
                      # ***  Use CORRECT output widget ***
                     self.shell_command_output.insert(tk.END, f"\nFailed to kill process after error: {kill_err}\n", ("error"))

        finally:
             # ***  Disable the CORRECT output area ***
             self.shell_command_output.configure(state='disabled')

# Keep the main execution block
if __name__ == "__main__":
    app = IOCExtractor()
    app.mainloop()
