# TLD's in the Domains key was pulled from https://data.iana.org/TLD/tlds-alpha-by-domain.txt
# File Names does not catch files with spaces correctly. Example: "test example.exe" ---> testexample.exe
# Domains does not capture SLD's correctly. Example: "example.uk.co ---> uk.co". 
# IPv6 catches mostly everything but also will catch catches times
# I do not think URLs that have b64 / url / or hex encodeing will get caught and URLs with a double "\\/" as well

"""
If Using a MAC, you must change the values in the VT frame so that the Buttons are clearly visable:

# VirusTotal Frame buttons for MAC
        self.vt_frame = tk.Frame(self)
        self.vt_frame.place(relx=1.0, rely=1.0, x=-10, y=-27, anchor="se")
        self.vt2_frame = tk.Frame(self)
        self.vt2_frame.place(relx=1.0, rely=1.0, x=-130, y=-27, anchor="se")
        self.vt3_frame = tk.Frame(self)
        self.vt3_frame.place(relx=1.0, rely=1.0, x=-243, y=-27, anchor="se")
        self.vt4_frame = tk.Frame(self)
        self.vt4_frame.place(relx=1.0, rely=1.0, x=-370, y=-27, anchor="se")
"""

import re
import time
import base64
import requests
import tkinter as tk
import tkinter.filedialog
import tkinter.simpledialog
import tkinter.messagebox
import tkinter.messagebox as messagebox
import os
from tkinter import scrolledtext

SEPARATOR_DEFANGS = r"[\(\)\[\]{}<>\\]"
END_PUNCTUATION = r"[\.\?>\"'\)!,}:;\u201d\u2019\uff1e\uff1c\]]*"
FILE_EXTENSIONS = r"(doc|docx|pdf|ppt|pptx|mui|txt|rtf|xls|xlsx|odt|jpeg|jpg|png|me|info|biz|gif|bmp|svg|tiff|psd|ico|mp3|wav|aac|flac|ogg|m4a|wma|mp4|avi|mkv|flv|mov|wmv|mpeg|zip|rar|7z|tar|gz|bz2|iso|html|htm|css|js|php|py|java|cpp|c|h|cs|sql|db|mdb|xml|json|exe|dll|sys|ini|bat|vbs|dwg|dxf|3ds|max|skp|proj|aep|prproj|veg|cad|stl|step|dat|csv|log|mat|nc|vmdk|vdi|img|qcow2|ttf|otf|fon|bak|tmp|dmp|epub|mobi|azw|azw3|git|svn|sh|bash|ps1|cmd|cfg|conf|yml|yaml|sass|scss|less|jsx|ts|tsx|npm|gem|pip|jar|deb|rpm|swf|lisp|go|rb|r|vmx|ova|ovf|vhdx|hdd|mid|midi|als|ftm|rex|unity|blend|unr|pak|bsp|pem|crt|csr|key|pgp|apk|ipa|app|aab|xapk|md|markdown|tex|bib|cls|vrml|x3d|u3d|ar|sbsar|ovpn|pcf|cisco|rdp|ssh|spss|sav|rdata|dta|do|ftl|twig|jinja|tpl|edml|obj|mtl|dae|abc|c4d|fbx|vrm|glb|gltf|usdz|reg|pol|inf|msi|msp|awk|sed|groovy|lua|tcl|gitignore|gitattributes|hgignore|dockerfile|dockerignore|sqlite|dbf|accdb|ora|frm|chm|mht|epub|mobi|lit|ai|eps|indd|xd|fig|rbw|pl|swift|kt|scala|ics|vcs|ical|zsh|fish)"
TLD = r"(?:com|org|top|ga|ml|info|cf|gq|icu|wang|live|cn|online|host|us|tk|fyi|buzz|net|io|gov|edu|eu|uk|de|fr|me|es|bid|shop|it|nl|ru|jp|in|br|au|ca|mx|nz|tv|cc|co|ro|us|asia|mobi|pro|tel|aero|travel|xyz|dagree|club|online|site|store|app|blog|design|tech|guru|ninja|news|media|network|agency|digital|email|link|click|world|today|solutions|tools|company|photography|tips|technology|works|zone|watch|video|guide|rodeo|life|chat|expert|haus|marketing|center|systems|academy|training|services|support|education|church|community|foundation|charity|ngo|ong|social|events|productions|fun|games|reviews|business|gdn|enterprises|international|land|properties|rentals|ventures|holdings|luxury|boutique|accountants|agency|associates|attorney|cc|construction|contractors|credit|dentist|engineer|equipment|estate|financial|florist|gallery|graphics|law|lawyer|management|marketing|media|photography|photos|productions|properties|realtor|realty|solutions|studio|systems|technology|ventures|vet|veterinarian|aaa|aarp|abb|abbott|abbvie|abc|able|abogado|abudhabi|ac|academy|accenture|accountant|accountants|aco|actor|ad|ads|adult|ae|aeg|aero|aetna|af|afl|africa|ag|agakhan|agency|ai|aig|airbus|airforce|airtel|akdn|al|alibaba|alipay|allfinanz|allstate|ally|alsace|alstom|am|amazon|americanexpress|americanfamily|amex|amfam|amica|amsterdam|analytics|android|anquan|anz|ao|aol|apartments|app|apple|aq|aquarelle|ar|arab|aramco|archi|army|arpa|art|arte|as|asda|asia|associates|at|athleta|attorney|au|auction|audi|audible|audio|auspost|author|auto|autos|avianca|aw|aws|ax|axa|az|azure|ba|baby|baidu|banamex|bananarepublic|band|bank|bar|barcelona|barclaycard|barclays|barefoot|bargains|baseball|basketball|bauhaus|bayern|bb|bbc|bbt|bbva|bcg|bcn|bd|be|beats|beauty|beer|bentley|berlin|best|bestbuy|bet|bf|bg|bh|bharti|bi|bible|bid|bike|bing|bingo|bio|biz|bj|black|blackfriday|blockbuster|blog|bloomberg|blue|bm|bms|bmw|bn|bnpparibas|bo|boats|boehringer|bofa|bom|bond|boo|book|booking|bosch|bostik|boston|bot|boutique|box|br|bradesco|bridgestone|broadway|broker|brother|brussels|bs|bt|build|builders|business|buy|buzz|bv|bw|by|bz|bzh|ca|cab|cafe|cal|call|calvinklein|cam|camera|camp|canon|capetown|capital|capitalone|car|caravan|cards|care|career|careers|cars|casa|case|cash|casino|cat|catering|catholic|cba|cbn|cbre|cbs|cc|cd|center|ceo|cern|cf|cfa|cfd|cg|ch|chanel|channel|charity|chase|chat|cheap|chintai|christmas|chrome|church|ci|cipriani|circle|cisco|citadel|citi|citic|city|cityeats|ck|cl|claims|cleaning|click|clinic|clinique|clothing|cloud|club|clubmed|cm|cn|co|coach|codes|coffee|college|cologne|com|comcast|commbank|community|company|compare|computer|comsec|condos|construction|consulting|contact|contractors|cooking|cool|coop|corsica|country|coupon|coupons|courses|cpa|cr|credit|creditcard|creditunion|cricket|crown|crs|cruise|cruises|cu|cuisinella|cv|cw|cx|cy|cymru|cyou|cz|dabur|dad|dance|data|date|dating|datsun|day|dclk|dds|de|deal|dealer|deals|degree|delivery|dell|deloitte|delta|democrat|dental|dentist|desi|design|dev|dhl|diamonds|diet|digital|direct|directory|discount|discover|dish|diy|dj|dk|dm|dnp|do|docs|doctor|dog|domains|dot|download|drive|dtv|dubai|dunlop|dupont|durban|dvag|dvr|dz|earth|eat|ec|eco|edeka|edu|education|ee|eg|email|emerck|energy|engineer|engineering|enterprises|epson|equipment|er|ericsson|erni|es|esq|estate|et|etisalat|eu|eurovision|eus|events|exchange|expert|exposed|express|extraspace|fage|fail|fairwinds|faith|family|fan|fans|farm|farmers|fashion|fast|fedex|feedback|ferrari|ferrero|fi|fidelity|fido|film|final|finance|financial|fire|firestone|firmdale|fish|fishing|fit|fitness|fj|fk|flickr|flights|flir|florist|flowers|fly|fm|fo|foo|food|football|ford|forex|forsale|forum|foundation|fox|fr|free|fresenius|frl|frogans|frontdoor|frontier|ftr|fujitsu|fun|fund|furniture|futbol|fyi|ga|gal|gallery|gallo|gallup|game|games|gap|garden|gay|gb|gbiz|gd|gdn|ge|gea|gent|genting|george|gf|gg|ggee|gh|gi|gift|gifts|gives|giving|gl|glass|gle|global|globo|gm|gmail|gmbh|gmo|gmx|gn|godaddy|gold|goldpoint|golf|goo|goodyear|goog|google|gop|got|gov|gp|gq|gr|grainger|graphics|gratis|green|gripe|grocery|group|gs|gt|gu|guardian|gucci|guge|guide|guitars|guru|gw|gy|hair|hamburg|hangout|haus|hbo|hdfc|hdfcbank|health|healthcare|help|helsinki|here|hermes|hiphop|hisamitsu|hitachi|hiv|hk|hkt|hm|hn|hockey|holdings|holiday|homedepot|homegoods|homes|homesense|honda|horse|hospital|host|hosting|hot|hotels|hotmail|house|how|hr|hsbc|ht|hu|hughes|hyatt|hyundai|ibm|icbc|ice|icu|id|ie|ieee|ifm|ikano|il|im|imamat|imdb|immo|immobilien|in|inc|industries|infiniti|info|ing|ink|institute|insurance|insure|int|international|intuit|investments|io|ipiranga|iq|ir|irish|is|ismaili|ist|istanbul|it|itau|itv|jaguar|java|jcb|je|jeep|jetzt|jewelry|jio|jll|jm|jmp|jnj|jo|jobs|joburg|jot|joy|jp|jpmorgan|jprs|juegos|juniper|kaufen|kddi|ke|kerryhotels|kerrylogistics|kerryproperties|kfh|kg|kh|ki|kia|kids|kim|kinder|kindle|kitchen|kiwi|km|kn|koeln|komatsu|kosher|kp|kpmg|kpn|kr|krd|kred|kuokgroup|kw|ky|kyoto|kz|la|lacaixa|lamborghini|lamer|lancaster|land|landrover|lanxess|lasalle|lat|latino|latrobe|law|lawyer|lb|lc|lds|lease|leclerc|lefrak|legal|lego|lexus|lgbt|li|lidl|life|lifeinsurance|lifestyle|lighting|like|lilly|limited|limo|lincoln|link|lipsy|live|living|lk|llc|llp|loan|loans|locker|locus|lol|london|lotte|lotto|love|lpl|lplfinancial|lr|ls|lt|ltd|ltda|lu|lundbeck|luxe|luxury|lv|ly|ma|madrid|maif|maison|makeup|man|management|mango|map|market|marketing|markets|marriott|marshalls|mattel|mba|mc|mckinsey|md|me|med|media|meet|melbourne|meme|memorial|men|menu|merckmsd|mg|mh|miami|microsoft|mil|mini|mint|mit|mitsubishi|mk|ml|mlb|mls|mm|mma|mn|mo|mobi|mobile|moda|moe|moi|mom|monash|money|monster|mormon|mortgage|moscow|moto|motorcycles|mov|movie|mp|mq|mr|ms|msd|mt|mtn|mtr|mu|museum|music|mv|mw|mx|my|mz|na|nab|nagoya|name|natura|navy|nba|nc|ne|nec|net|netbank|netflix|network|neustar|new|news|next|nextdirect|nexus|nf|nfl|ng|ngo|nhk|ni|nico|nike|nikon|ninja|nissan|nissay|nl|no|nokia|norton|now|nowruz|nowtv|np|nr|nra|nrw|ntt|nu|nyc|nz|obi|observer|office|okinawa|olayan|olayangroup|oldnavy|ollo|om|omega|one|ong|onl|online|ooo|open|oracle|orange|org|organic|origins|osaka|otsuka|ott|ovh|pa|page|panasonic|paris|pars|partners|parts|party|pay|pccw|pe|pet|pf|pfizer|pg|ph|pharmacy|phd|philips|phone|photo|photography|photos|physio|pics|pictet|pictures|pid|pin|ping|pink|pioneer|pizza|pk|pl|place|play|playstation|plumbing|plus|pm|pn|pnc|pohl|poker|politie|porn|post|pr|pramerica|praxi|press|prime|pro|prod|productions|prof|progressive|promo|properties|property|protection|pru|prudential|ps|pt|pub|pw|pwc|py|qa|qpon|quebec|quest|racing|radio|re|read|realestate|realtor|realty|recipes|red|redstone|redumbrella|rehab|reise|reisen|reit|reliance|ren|rent|rentals|repair|report|republican|rest|restaurant|review|reviews|rexroth|rich|richardli|ricoh|ril|rio|rip|ro|rocher|rocks|rodeo|rogers|room|rs|rsvp|ru|rugby|ruhr|run|rw|rwe|ryukyu|sa|saarland|safe|safety|sakura|sale|salon|samsclub|samsung|sandvik|sandvikcoromant|sanofi|sap|sarl|sas|save|saxo|sb|sbi|sbs|sc|sca|scb|schaeffler|schmidt|scholarships|school|schule|schwarz|science|scot|sd|se|search|seat|secure|security|seek|select|sener|services|seven|sew|sex|sexy|sfr|sg|sh|shangrila|sharp|shaw|shell|shia|shiksha|shoes|shop|shopping|shouji|show|showtime|si|silk|sina|singles|site|sj|sk|ski|skin|sky|skype|sl|sling|sm|smart|smile|sn|sncf|so|soccer|social|softbank|software|sohu|solar|solutions|song|sony|soy|spa|space|sport|spot|sr|srl|ss|st|stada|staples|star|statebank|statefarm|stc|stcgroup|stockholm|storage|store|stream|studio|study|style|su|sucks|supplies|supply|support|surf|surgery|suzuki|sv|swatch|swiss|sx|sy|sydney|systems|sz|tab|taipei|talk|taobao|target|tatamotors|tatar|tattoo|tax|taxi|tc|tci|td|tdk|team|tech|technology|tel|temasek|tennis|teva|tf|tg|th|thd|theater|theatre|tiaa|tickets|tienda|tips|tires|tirol|tj|tjmaxx|tjx|tk|tkmaxx|tl|tm|tmall|tn|to|today|tokyo|tools|top|toray|toshiba|total|tours|town|toyota|toys|tr|trade|trading|training|travel|travelers|travelersinsurance|trust|trv|tt|tube|tui|tunes|tushu|tv|tvs|tw|tz|ua|ubank|ubs|ug|uk|unicom|university|uno|uol|ups|us|uy|uz|va|vacations|vana|vanguard|vc|ve|vegas|ventures|verisign|versicherung|vet|vg|vi|viajes|video|vig|viking|villas|vin|vip|virgin|visa|vision|viva|vivo|vlaanderen|vn|vodka|volkswagen|volvo|vote|voting|voto|voyage|vu|wales|walmart|walter|wang|wanggou|watch|watches|weather|weatherchannel|webcam|weber|website|wed|wedding|weibo|weir|wf|whoswho|wien|wiki|williamhill|win|windows|wine|winners|wme|wolterskluwer|woodside|work|works|world|wow|ws|wtc|wtf|xbox|xerox|xfinity|xihuan|xin|xn--11b4c3d|xn--1ck2e1b|xn--1qqw23a|xn--2scrj9c|xn--30rr7y|xn--3bst00m|xn--3ds443g|xn--3e0b707e|xn--3hcrj9c|xn--3pxu8k|xn--42c2d9a|xn--45br5cyl|xn--45brj9c|xn--45q11c|xn--4dbrk0ce|xn--4gbrim|xn--54b7fta0cc|xn--55qw42g|xn--55qx5d|xn--5su34j936bgsg|xn--5tzm5g|xn--6frz82g|xn--6qq986b3xl|xn--80adxhks|xn--80ao21a|xn--80aqecdr1a|xn--80asehdb|xn--80aswg|xn--8y0a063a|xn--90a3ac|xn--90ae|xn--90ais|xn--9dbq2a|xn--9et52u|xn--9krt00a|xn--b4w605ferd|xn--bck1b9a5dre4c|xn--c1avg|xn--c2br7g|xn--cck2b3b|xn--cckwcxetd|xn--cg4bki|xn--clchc0ea0b2g2a9gcd|xn--czr694b|xn--czrs0t|xn--czru2d|xn--d1acj3b|xn--d1alf|xn--e1a4c|xn--eckvdtc9d|xn--efvy88h|xn--fct429k|xn--fhbei|xn--fiq228c5hs|xn--fiq64b|xn--fiqs8s|xn--fiqz9s|xn--fjq720a|xn--flw351e|xn--fpcrj9c3d|xn--fzc2c9e2c|xn--fzys8d69uvgm|xn--g2xx48c|xn--gckr3f0f|xn--gecrj9c|xn--gk3at1e|xn--h2breg3eve|xn--h2brj9c|xn--h2brj9c8c|xn--hxt814e|xn--i1b6b1a6a2e|xn--imr513n|xn--io0a7i|xn--j1aef|xn--j1amh|xn--j6w193g|xn--jlq480n2rg|xn--jvr189m|xn--kcrx77d1x4a|xn--kprw13d|xn--kpry57d|xn--kput3i|xn--l1acc|xn--lgbbat1ad8j|xn--mgb9awbf|xn--mgba3a3ejt|xn--mgba3a4f16a|xn--mgba7c0bbn0a|xn--mgbaakc7dvf|xn--mgbaam7a8h|xn--mgbab2bd|xn--mgbah1a3hjkrd|xn--mgbai9azgqp6j|xn--mgbayh7gpa|xn--mgbbh1a|xn--mgbbh1a71e|xn--mgbc0a9azcg|xn--mgbca7dzdo|xn--mgbcpq6gpa1a|xn--mgberp4a5d4ar|xn--mgbgu82a|xn--mgbi4ecexp|xn--mgbpl2fh|xn--mgbt3dhd|xn--mgbtx2b|xn--mgbx4cd0ab|xn--mix891f|xn--mk1bu44c|xn--mxtq1m|xn--ngbc5azd|xn--ngbe9e0a|xn--ngbrx|xn--node|xn--nqv7f|xn--nqv7fs00ema|xn--nyqy26a|xn--o3cw4h|xn--ogbpf8fl|xn--otu796d|xn--p1acf|xn--p1ai|xn--pgbs0dh|xn--pssy2u|xn--q7ce6a|xn--q9jyb4c|xn--qcka1pmc|xn--qxa6a|xn--qxam|xn--rhqv96g|xn--rovu88b|xn--rvc1e0am3e|xn--s9brj9c|xn--ses554g|xn--t60b56a|xn--tckwe|xn--tiq49xqyj|xn--unup4y|xn--vermgensberater-ctb|xn--vermgensberatung-pwb|xn--vhquv|xn--vuq861b|xn--w4r85el8fhu5dnra|xn--w4rs40l|xn--wgbh1c|xn--wgbl6a|xn--xhq521b|xn--xkc2al3hye2a|xn--xkc2dl3a5ee0h|xn--y9a3aq|xn--yfro4i67o|xn--ygbi2ammx|xn--zfr164b|xxx|xyz|yachts|yahoo|yamaxun|yandex|ye|yodobashi|yoga|yokohama|you|youtube|yt|yun|za|zappos|zara|zero|zip|zm|zone|zuerich|zw)"

regexes = { #catch IPv4 without defang
    'IPv4': re.compile(r'\b(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.|\[\.\])(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.|\[\.\])(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.|\[\.\])(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'),
    'IPv6': re.compile(r'(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:|(?:[A-Fa-f0-9]{1,4}:){1,6}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}|:(?::[A-Fa-f0-9]{1,4}){1,7}|::[A-Fa-f0-9]{1,4}|::|'),
    'Domains': re.compile((r"(?<![@a-zA-Z0-9._%+-])([a-zA-Z0-9\-]+(?:\.|\[\.\]){0})\b").format(TLD)),
    'Sub Domains': re.compile(r'(?<![@a-zA-Z0-9._%+-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.|\[\.]))+[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.|\[\.])[a-zA-Z]{2,}'),
    'URLs': re.compile(r"([fhstu]\S\S?[px]s?(?::\/\/|:\\\\|\[:\]\/\/|\[:\/\/\]|:?__)(?:\x20|" + SEPARATOR_DEFANGS + r")*\w\S+?(?:\x20[\/\.][^\.\/\s]\S*?)*)(?=\s|[^\x00-\x7F]|$)", re.IGNORECASE | re.VERBOSE | re.UNICODE), 
    'IP URL': re.compile(r'hxxps?:\/\/(?:\d{1,3}\.|\[\.\])?(?:\d{1,3}\.|\[\.\])?(?:\d{1,3}\.|\[\.\])?\d{1,3}(?:\[\.\]\d{1,3})?\/\d+\/[a-f0-9]+'), 
    'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'), 
    'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'), 
    'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'), 
    'CVEs': re.compile(r'(?:CVE-\d{4}-\d{4,}|CVE[\s\[\(]\d{4}-\d{4,}[\]\)])'),
    'File Names': re.compile((r"""(?<=[\"\'])+\s[^\"\']+\.{0}(?=[\"\'])|(?<![\"\'])\b[^'\" \t\n\r\f\v/\\]+?\.{0}\b(?![\"\'])""").format(FILE_EXTENSIONS), re.VERBOSE),
    'Email Addresses': re.compile(r"""([a-z0-9_.+-]+[\(\[{\x20]*(?:(?:(?:\x20*""" + SEPARATOR_DEFANGS + r"""\x20*)*\.(?:\x20*""" + SEPARATOR_DEFANGS + r"""\x20*)*|\W+dot\W+)[a-z0-9-]+?)*[a-z0-9_.+-]+[\(\[{\x20]*(?:@|\Wat\W)[\)\]}\x20]*[a-z0-9-]+(?:(?:(?:\x20*""" + SEPARATOR_DEFANGS + r"""\x20*)*\.(?:\x20*""" + SEPARATOR_DEFANGS + r"""\x20*)*|\W+dot\W+)[a-z0-9-]+?)+)""" + END_PUNCTUATION + r"""(?=\s|$)""", re.IGNORECASE | re.VERBOSE | re.UNICODE,),
    'Registry': re.compile(r'\b((HKLM|HKCU)\\[\\A-Za-z0-9-_]+)\b'),
    'Mac Address': re.compile(r'\b(?:[A-Fa-f0-9]{2}([-:]))(?:[A-Fa-f0-9]{2}\1){4}[A-Fa-f0-9]{2}\b'),
    'Bitcoin Addresses': re.compile(r'\b[13][a-km-zA-HJ-NP-Z0-9]{26,33}\b'),
    'Yara Rules': re.compile(r"""(?:^|\s)((?:\s*?import\s+?"[^\r\n]*?[\r\n]+|\s*?include\s+?"[^\r\n]*?[\r\n]+|\s*?//[^\r\n]*[\r\n]+|\s*?/\*.*?\*/\s*?)*(?:\s*?private\s+|\s*?global\s+)*rule\s*?\w+\s*?(?::[\s\w]+)?\s+\{.*?condition\s*?:.*?\s*\})(?:$|\s)""",re.MULTILINE | re.DOTALL | re.VERBOSE,),
}

class IOCExtractor(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IOC Extractor")
        self.iconbitmap('')
        self.geometry("1600x800")
        
        # Article Input
        self.article_input = scrolledtext.ScrolledText(self, wrap=tk.WORD, height=10, bg='light grey', fg='black')
        self.article_input.pack(expand=1, fill='both')
        self.article_input.insert(tk.END, "Input Text Here...")
        self.article_input.bind("<Key>", self.on_input)
        self.article_input.bind("<Button-1>", self.on_input)
        
        # Review Output
        self.review_output = scrolledtext.ScrolledText(self, wrap=tk.WORD, height=10, bg='Burlywood', fg='black')
        self.review_output.pack(expand=1, fill='both')
        self.review_output.insert(tk.END, "Extracted IOCs will be displayed here...")
        self.review_output.configure(state='disable')
        self.review_output.tag_configure("highlight", background="yellow")
        
        # Buttons
        self.parse_button = tk.Button(self, text="Parse IOCs", command=self.parse_iocs, fg='black', bg='green')
        self.parse_button.pack(side=tk.BOTTOM, fill='x')
        self.defang_button = tk.Button(self, text="Defang IOCs", command=self.defang_iocs, fg='black', bg='Light Sea Green')
        self.defang_button.pack(side=tk.RIGHT, fill='x')
        self.save_button = tk.Button(self, text="Save Group", command=self.save_iocs, fg='black', bg='Light Sea Green')
        self.save_button.pack(side=tk.RIGHT, fill='x')
        self.save_folder_button = tk.Button(self, text="Save Individually", command=self.save_iocs_to_folder, fg='black', bg='Light Sea Green')
        self.save_folder_button.pack(side=tk.RIGHT, fill='x')
        self.modify_iocs_button = tk.Button(self, text="Add IOC", command=self.add_ioc_to_category, fg='black', bg='Light Sea Green')
        self.modify_iocs_button.pack(side=tk.RIGHT, fill='x')
        self.remove_ioc_button = tk.Button(self, text="Remove IOC", command=self.remove_ioc, fg='black', bg='Light Sea Green')
        self.remove_ioc_button.pack(side=tk.RIGHT, fill='x')
        
        # VirusTotal Frame
        self.vt_frame = tk.Frame(self)
        self.vt_frame.place(relx=1.0, rely=1.0, x=-10, y=-27, anchor="se")
        self.vt2_frame = tk.Frame(self)
        self.vt2_frame.place(relx=1.0, rely=1.0, x=-95, y=-27, anchor="se")
        self.vt3_frame = tk.Frame(self)
        self.vt3_frame.place(relx=1.0, rely=1.0, x=-170, y=-27, anchor="se")
        self.vt4_frame = tk.Frame(self)
        self.vt4_frame.place(relx=1.0, rely=1.0, x=-260, y=-27, anchor="se")

        # VT Button inside VT Frame
        self.vt_button = tk.Button(self.vt_frame, text="VT URL Check", command=self.on_vt_button_click, fg='black', bg='Light Sea Green')
        self.vt_button.pack(pady=10)

        # VT Submit for Analysis
        self.submit_url_button = tk.Button(self.vt2_frame, text="VT URL Scan", command=self.submit_url_for_analysis, fg='black', bg='Light Sea Green')
        self.submit_url_button.pack(pady=10)
        
        #VT Analyze Hahs
        self.submit_hash_button = tk.Button(self.vt3_frame, text="VT Hash Check", command=self.submit_hash_for_analysis, fg='black', bg='Light Sea Green')
        self.submit_hash_button.pack(pady=10)

        #VT get all hashes
        self.all_hashes_button = tk.Button(self.vt4_frame, text="VT Get Hashes", command=self.submit_hash_for_all_hashes, fg='black', bg='Light Sea Green')
        self.all_hashes_button.pack(pady=10)

        # VT Results Output
        self.vt_results_output = scrolledtext.ScrolledText(self, wrap=tk.WORD, height=7, bg='light blue', fg='black')
        self.vt_results_output.pack(expand=1, fill='both')
        self.vt_results_output.insert(tk.END, "VirusTotal results will be displayed here...")
        self.vt_results_output.configure(state='disable')

    #\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\Important\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\    
    VIRUSTOTAL_API_KEY = '' # Enter your API Key Here
     #\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\Important\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    def on_input(self, event):
        content = self.article_input.get("1.0", tk.END).strip()
        if content == "Input Text Here...":
            self.article_input.delete("1.0", tk.END)

    def query_virustotal(self, ioc):
        headers = {
            "Accept": "application/json",
            "x-apikey": self.VIRUSTOTAL_API_KEY
        }

        if self.is_url(ioc):
            # Encode the URL in Base64
            encoded_url = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")

            # Retrieve the analysis results using the encoded URL
            url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
            report_link = f"https://www.virustotal.com/gui/url/{encoded_url}/detection"
        else:  # Assuming it's a hash
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            if response.status_code != 200:
                error_message = response.json().get('error', {}).get('message', 'Unknown error')
                if "not found" in error_message:
                    return f"URL not scanned on VirusTotal. Consider submitting it for analysis."
                else:
                    return f"Error querying VirusTotal: {error_message}"
        data = response.json()

        # Extract relevant information from the response
        if 'data' in data:
            attributes = data['data']['attributes']
            ratio = attributes['last_analysis_stats']
            malicious = ratio['malicious']
            undetected = ratio['undetected']
            return f"Malicious: {malicious}, Undetected: {undetected}, Link: {report_link}"
        else:
            return "Error querying VirusTotal"

    def is_url(self, string):
        return string.startswith("http://") or string.startswith("https://") or (' ')
    
    def on_vt_button_click(self):
        # Get the selected IOC(s) from the review_output widget
        iocs = self.review_output.get(tk.SEL_FIRST, tk.SEL_LAST).split('\n')
        
        results = []
        for ioc in iocs:
            if ioc:  # Check if the string is not empty
                result = self.query_virustotal(ioc.strip())
                results.append((ioc, result))
        
        # Display the results in the vt_results_output widget
        self.vt_results_output.configure(state='normal')  # Make it writable
        self.vt_results_output.delete(1.0, tk.END)  # Clear previous results
        
        # Define a bold tag
        self.vt_results_output.tag_configure("bold", font=("Arial", 10, "bold"))
        
        for ioc, result in results:
            # Insert the URL with the bold tag
            self.vt_results_output.insert(tk.END, ioc + ":\n", "bold")
            self.vt_results_output.insert(tk.END, result + "\n\n")
        
        self.vt_results_output.configure(state='disable')

    def submit_url_for_analysis(self):
        # Get the selected URL(s) from the review_output widget
        urls = self.review_output.get(tk.SEL_FIRST, tk.SEL_LAST).split('\n')
        
        headers = {
            "Accept": "application/json",
            "x-apikey": self.VIRUSTOTAL_API_KEY
        }
        
        submit_url_endpoint = "https://www.virustotal.com/api/v3/urls"
        
        # Clear the vt_results_output widget and make it writable
        self.vt_results_output.configure(state='normal')
        self.vt_results_output.delete(1.0, tk.END)
        
        # Define a bold tag for the widget
        self.vt_results_output.tag_configure("bold", font=("Arial", 10, "bold"))
        
        for url in urls:
            if url:  # Check if the string is not empty
                data = {"url": url.strip()}
                response = requests.post(submit_url_endpoint, headers=headers, data=data)
                
                if response.status_code == 200:
                    # The URL was successfully submitted for analysis
                    analysis_id = response.json().get("data", {}).get("id", "")
                    analysis_url = f"https://www.virustotal.com/gui/url-analysis/ui-id/{analysis_id}/detection"
                    # Display the success message and analysis URL in the vt_results_output widget
                    self.vt_results_output.insert(tk.END, f"URL {url}:\n", "bold")
                    self.vt_results_output.insert(tk.END, f"Submitted successfully. Analysis ID: {analysis_id}\n")
                    self.vt_results_output.insert(tk.END, f"Analysis URL: {analysis_url}\n\n")
                else:
                    # There was an error submitting the URL
                    error_message = response.json().get('error', {}).get('message', 'Unknown error')
                    # Display the error message in the vt_results_output widget
                    self.vt_results_output.insert(tk.END, f"URL {url}:\n", "bold")
                    self.vt_results_output.insert(tk.END, f"Error submitting for analysis: {error_message}\n\n")
        
        # Make the vt_results_output widget read-only again
        self.vt_results_output.configure(state='disable')

    def submit_hash_for_analysis(self):
        
        hashes = self.review_output.get(tk.SEL_FIRST, tk.SEL_LAST).split('\n')
        headers = {
            "Accept": "application/json",
            "x-apikey": self.VIRUSTOTAL_API_KEY
        }
        self.vt_results_output.configure(state='normal')
        self.vt_results_output.delete(1.0, tk.END)
        self.vt_results_output.tag_configure("bold", font=("Arial", 10, "bold"))

        for hashing in hashes:
            hashing = hashing.strip()  # Remove any leading or trailing whitespace
            if hashing and len(hashing) == 64:  # Ensure it's a valid SHA-256 hash length
                submit_url_endpoint = f"https://www.virustotal.com/api/v3/files/{hashing}/analyse"
                try:
                    response = requests.post(submit_url_endpoint, headers=headers)
                    response_data = response.json()
                    if 200 <= response.status_code < 300:
                        analysis_id = response_data.get("data", {}).get("id", "")
                        analysis_url = f"https://www.virustotal.com/gui/file/{hashing}"
                        self.vt_results_output.insert(tk.END, f"Hash {hashing}:\n", "bold")
                        self.vt_results_output.insert(tk.END, f"Submitted successfully. Analysis ID: {analysis_id}\n")
                        self.vt_results_output.insert(tk.END, f"Virus Total GUI: {analysis_url}\n\n")
                    else:
                        error_message = response_data.get('error', {}).get('message', 'Unknown error')
                        self.vt_results_output.insert(tk.END, f"URL {hashing}:\n", "bold")
                        self.vt_results_output.insert(tk.END, f"Error submitting for analysis: {error_message}\n\n")
                except (ValueError, requests.RequestException) as e:
                    self.vt_results_output.insert(tk.END, f"URL {hashing}:\n", "bold")
                    self.vt_results_output.insert(tk.END, f"Error: {str(e)}\n\n")

        self.vt_results_output.configure(state='disable')

    def submit_hash_for_all_hashes(self):
        hashes = self.review_output.get(tk.SEL_FIRST, tk.SEL_LAST).split('\n')
        headers = {
            "Accept": "application/json",
            "x-apikey": self.VIRUSTOTAL_API_KEY
        }
        self.vt_results_output.configure(state='normal')
        self.vt_results_output.delete(1.0, tk.END)
        self.vt_results_output.tag_configure("bold", font=("Arial", 10, "bold"))

        for hashing in hashes:
            hashing = hashing.strip()  # Remove any leading or trailing whitespace
            if hashing and len(hashing) == 64:  # Ensure it's a valid SHA-256 hash length
                hash_details = self.get_hash_details(hashing)
                if "error" not in hash_details:
                    self.vt_results_output.insert(tk.END, f"Hash {hashing}:\n", "bold")
                    self.vt_results_output.insert(tk.END, f"MD5: {hash_details['md5']}\n")
                    self.vt_results_output.insert(tk.END, f"SHA-1: {hash_details['sha1']}\n")
                    self.vt_results_output.insert(tk.END, f"SHA-256: {hash_details['sha256']}\n\n")
                else:
                    self.vt_results_output.insert(tk.END, f"Hash {hashing}:\n", "bold")
                    self.vt_results_output.insert(tk.END, f"Error: {hash_details['error']}\n\n")

        self.vt_results_output.configure(state='disable')

    def get_hash_details(self, hash_value):
        headers = {
            "Accept": "application/json",
            "x-apikey": self.VIRUSTOTAL_API_KEY
        }
        
        # Endpoint to retrieve file details
        file_info_endpoint = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        
        response = requests.get(file_info_endpoint, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            
            # Extracting associated hashes
            md5 = attributes.get("md5", "Not available")
            sha1 = attributes.get("sha1", "Not available")
            sha256 = attributes.get("sha256", "Not available")
            
            return {
                "md5": md5,
                "sha1": sha1,
                "sha256": sha256
            }
        else:
            # Handle error
            try:
                error_message = response.json().get('error', {}).get('message', 'Unknown error')
            except ValueError:
                error_message = "Unknown error"
            return {"error": error_message}

    def refang(self, value: str) -> str:
        # Refang the defanged IPs and URLs
        value = value.replace('[.]', '.')  
        value = value.replace('hxxp', 'http')
        value = value.replace('hxxps', 'https')
        value = value.replace('hXXp', 'http')
        value = value.replace('hXXps', 'https')
        value = value.replace("[dot]", ".")
        value = value.replace("(dot)", ".")
        value = value.replace("[.]", ".")
        value = value.replace("(", "")
        value = value.replace(")", "")
        value = value.replace(",", ".")
        value = value.replace(" ", "")
        value = value.replace("\u30fb", ".")
        value = value.replace('HTtp', 'http')
        value = value.replace('HTTp', 'http')
        value = value.replace('HTtP', 'http')
        value = value.replace('HTTP', 'http')
        value = value.replace('HtTp', 'http')
        value = value.replace('HtTP', 'http')
        value = value.replace('HttP', 'http')
        value = value.replace('Http', 'http')
        value = value.replace('hTtp', 'http')
        value = value.replace('hTTp', 'http')
        value = value.replace('hTtP', 'http')
        value = value.replace('hTTP', 'http')
        value = value.replace('htTp', 'http')
        value = value.replace('htTP', 'http')
        value = value.replace('httP', 'http')
        value = value.replace('HTtps', 'https')
        value = value.replace('HTTps', 'https')
        value = value.replace('HTtPs', 'https')
        value = value.replace('HTTPs', 'https')
        value = value.replace('HtTps', 'https')
        value = value.replace('HtTPs', 'https')
        value = value.replace('HttPs', 'https')
        value = value.replace('Https', 'https')
        value = value.replace('hTtps', 'https')
        value = value.replace('hTTps', 'https')
        value = value.replace('hTtPs', 'https')
        value = value.replace('hTPs', 'https')
        value = value.replace('htTps', 'https')
        value = value.replace('htTPs', 'https')
        value = value.replace('httPs', 'https')
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
        
        #filtered_url = {url for url in iocs['URLs'] if re.match(r'(?i)^(http|hxxp|ftp|sftp|hXXp|hXXps|https)s?://', url)}    Part of old regex match
        #iocs['URLs'] = filtered_url
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
