#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_web_category_category_list
description:
    - List of web categories
short_description: Configures A10 web-category.category-list
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    streaming_media:
        description:
        - "Category Streaming Media"
        required: False
    weapons:
        description:
        - "Category Weapons"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    entertainment_and_arts:
        description:
        - "Category Entertainment and Arts"
        required: False
    cdns:
        description:
        - "Category CDNs"
        required: False
    financial_services:
        description:
        - "Category Financial Services"
        required: False
    social_network:
        description:
        - "Category Social Network"
        required: False
    government:
        description:
        - "Category Government"
        required: False
    web_advertisements:
        description:
        - "Category Web Advertisements"
        required: False
    fashion_and_beauty:
        description:
        - "Category Fashion and Beauty"
        required: False
    computer_and_internet_security:
        description:
        - "Category Computer and Internet Security"
        required: False
    name:
        description:
        - "Web Category List name"
        required: True
    real_estate:
        description:
        - "Category Real Estate"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    web_based_email:
        description:
        - "Category Web based email"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'uncategorized'= uncategorized category; 'real-estate'= real estate category; 'computer-and-internet-security'= computer and internet security category; 'financial-services'= financial services category; 'business-and-economy'= business and economy category; 'computer-and-internet-info'= computer and internet info category; 'auctions'= auctions category; 'shopping'= shopping category; 'cult-and-occult'= cult and occult category; 'travel'= travel category; 'drugs'= drugs category; 'adult-and-pornography'= adult and pornography category; 'home-and-garden'= home and garden category; 'military'= military category; 'social-network'= social network category; 'dead-sites'= dead sites category; 'stock-advice-and-tools'= stock advice and tools category; 'training-and-tools'= training and tools category; 'dating'= dating category; 'sex-education'= sex education category; 'religion'= religion category; 'entertainment-and-arts'= entertainment and arts category; 'personal-sites-and-blogs'= personal sites and blogs category; 'legal'= legal category; 'local-information'= local information category; 'streaming-media'= streaming media category; 'job-search'= job search category; 'gambling'= gambling category; 'translation'= translation category; 'reference-and-research'= reference and research category; 'shareware-and-freeware'= shareware and freeware category; 'peer-to-peer'= peer to peer category; 'marijuana'= marijuana category; 'hacking'= hacking category; 'games'= games category; 'philosophy-and-politics'= philosophy and politics category; 'weapons'= weapons category; 'pay-to-surf'= pay to surf category; 'hunting-and-fishing'= hunting and fishing category; 'society'= society category; 'educational-institutions'= educational institutions category; 'online-greeting-cards'= online greeting cards category; 'sports'= sports category; 'swimsuits-and-intimate-apparel'= swimsuits and intimate apparel category; 'questionable'= questionable category; 'kids'= kids category; 'hate-and-racism'= hate and racism category; 'personal-storage'= personal storage category; 'violence'= violence category; 'keyloggers-and-monitoring'= keyloggers and monitoring category; 'search-engines'= search engines category; 'internet-portals'= internet portals category; 'web-advertisements'= web advertisements category; 'cheating'= cheating category; 'gross'= gross category; 'web-based-email'= web based email category; 'malware-sites'= malware sites category; 'phishing-and-other-fraud'= phishing and other fraud category; 'proxy-avoid-and-anonymizers'= proxy avoid and anonymizers category; 'spyware-and-adware'= spyware and adware category; 'music'= music category; 'government'= government category; 'nudity'= nudity category; 'news-and-media'= news and media category; 'illegal'= illegal category; 'CDNs'= content delivery networks category; 'internet-communications'= internet communications category; 'bot-nets'= bot nets category; 'abortion'= abortion category; 'health-and-medicine'= health and medicine category; 'confirmed-SPAM-sources'= confirmed SPAM sources category; 'SPAM-URLs'= SPAM URLs category; 'unconfirmed-SPAM-sources'= unconfirmed SPAM sources category; 'open-HTTP-proxies'= open HTTP proxies category; 'dynamic-comment'= dynamic comment category; 'parked-domains'= parked domains category; 'alcohol-and-tobacco'= alcohol and tobacco category; 'private-IP-addresses'= private IP addresses category; 'image-and-video-search'= image and video search category; 'fashion-and-beauty'= fashion and beauty category; 'recreation-and-hobbies'= recreation and hobbies category; 'motor-vehicles'= motor vehicles category; 'web-hosting-sites'= web hosting sites category; 'food-and-dining'= food and dining category; "
    recreation_and_hobbies:
        description:
        - "Category Recreation and Hobbies"
        required: False
    business_and_economy:
        description:
        - "Category Business and Economy"
        required: False
    confirmed_spam_sources:
        description:
        - "Category Confirmed SPAM Sources"
        required: False
    philosophy_and_politics:
        description:
        - "Category Philosophy and Political Advocacy"
        required: False
    society:
        description:
        - "Category Society"
        required: False
    motor_vehicles:
        description:
        - "Category Motor Vehicles"
        required: False
    proxy_avoid_and_anonymizers:
        description:
        - "Category Proxy Avoid and Anonymizers"
        required: False
    gross:
        description:
        - "Category Gross"
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            philosophy_and_politics:
                description:
                - "philosophy and politics category"
            stock_advice_and_tools:
                description:
                - "stock advice and tools category"
            news_and_media:
                description:
                - "news and media category"
            business_and_economy:
                description:
                - "business and economy category"
            peer_to_peer:
                description:
                - "peer to peer category"
            phishing_and_other_fraud:
                description:
                - "phishing and other fraud category"
            nudity:
                description:
                - "nudity category"
            weapons:
                description:
                - "weapons category"
            CDNs:
                description:
                - "content delivery networks category"
            marijuana:
                description:
                - "marijuana category"
            home_and_garden:
                description:
                - "home and garden category"
            cult_and_occult:
                description:
                - "cult and occult category"
            society:
                description:
                - "society category"
            unconfirmed_SPAM_sources:
                description:
                - "unconfirmed SPAM sources category"
            personal_storage:
                description:
                - "personal storage category"
            computer_and_internet_security:
                description:
                - "computer and internet security category"
            food_and_dining:
                description:
                - "food and dining category"
            motor_vehicles:
                description:
                - "motor vehicles category"
            swimsuits_and_intimate_apparel:
                description:
                - "swimsuits and intimate apparel category"
            dead_sites:
                description:
                - "dead sites category"
            translation:
                description:
                - "translation category"
            proxy_avoid_and_anonymizers:
                description:
                - "proxy avoid and anonymizers category"
            financial_services:
                description:
                - "financial services category"
            gross:
                description:
                - "gross category"
            cheating:
                description:
                - "cheating category"
            entertainment_and_arts:
                description:
                - "entertainment and arts category"
            sex_education:
                description:
                - "sex education category"
            illegal:
                description:
                - "illegal category"
            travel:
                description:
                - "travel category"
            local_information:
                description:
                - "local information category"
            legal:
                description:
                - "legal category"
            sports:
                description:
                - "sports category"
            bot_nets:
                description:
                - "bot nets category"
            religion:
                description:
                - "religion category"
            private_IP_addresses:
                description:
                - "private IP addresses category"
            music:
                description:
                - "music category"
            hate_and_racism:
                description:
                - "hate and racism category"
            open_HTTP_proxies:
                description:
                - "open HTTP proxies category"
            internet_communications:
                description:
                - "internet communications category"
            shareware_and_freeware:
                description:
                - "shareware and freeware category"
            dating:
                description:
                - "dating category"
            spyware_and_adware:
                description:
                - "spyware and adware category"
            uncategorized:
                description:
                - "uncategorized category"
            questionable:
                description:
                - "questionable category"
            reference_and_research:
                description:
                - "reference and research category"
            web_advertisements:
                description:
                - "web advertisements category"
            streaming_media:
                description:
                - "streaming media category"
            social_network:
                description:
                - "social network category"
            government:
                description:
                - "government category"
            drugs:
                description:
                - "drugs category"
            web_hosting_sites:
                description:
                - "web hosting sites category"
            malware_sites:
                description:
                - "malware sites category"
            name:
                description:
                - "Web Category List name"
            pay_to_surf:
                description:
                - "pay to surf category"
            kids:
                description:
                - "kids category"
            gambling:
                description:
                - "gambling category"
            online_greeting_cards:
                description:
                - "online greeting cards category"
            health_and_medicine:
                description:
                - "health and medicine category"
            SPAM_URLs:
                description:
                - "SPAM URLs category"
            image_and_video_search:
                description:
                - "image and video search category"
            educational_institutions:
                description:
                - "educational institutions category"
            keyloggers_and_monitoring:
                description:
                - "keyloggers and monitoring category"
            hunting_and_fishing:
                description:
                - "hunting and fishing category"
            search_engines:
                description:
                - "search engines category"
            fashion_and_beauty:
                description:
                - "fashion and beauty category"
            dynamic_comment:
                description:
                - "dynamic comment category"
            computer_and_internet_info:
                description:
                - "computer and internet info category"
            real_estate:
                description:
                - "real estate category"
            internet_portals:
                description:
                - "internet portals category"
            shopping:
                description:
                - "shopping category"
            violence:
                description:
                - "violence category"
            abortion:
                description:
                - "abortion category"
            hacking:
                description:
                - "hacking category"
            training_and_tools:
                description:
                - "training and tools category"
            web_based_email:
                description:
                - "web based email category"
            personal_sites_and_blogs:
                description:
                - "personal sites and blogs category"
            games:
                description:
                - "games category"
            parked_domains:
                description:
                - "parked domains category"
            auctions:
                description:
                - "auctions category"
            job_search:
                description:
                - "job search category"
            recreation_and_hobbies:
                description:
                - "recreation and hobbies category"
            confirmed_SPAM_sources:
                description:
                - "confirmed SPAM sources category"
            alcohol_and_tobacco:
                description:
                - "alcohol and tobacco category"
            adult_and_pornography:
                description:
                - "adult and pornography category"
            military:
                description:
                - "military category"
    legal:
        description:
        - "Category Legal"
        required: False
    bot_nets:
        description:
        - "Category Bot Nets"
        required: False
    religion:
        description:
        - "Category Religion"
        required: False
    private_ip_addresses:
        description:
        - "Category Private IP Addresses"
        required: False
    dating:
        description:
        - "Category Dating"
        required: False
    pay_to_surf:
        description:
        - "Category Pay to Surf"
        required: False
    reference_and_research:
        description:
        - "Category Reference and Research"
        required: False
    keyloggers_and_monitoring:
        description:
        - "Category Keyloggers and Monitoring"
        required: False
    kids:
        description:
        - "Category Kids"
        required: False
    online_greeting_cards:
        description:
        - "Category Online Greeting cards"
        required: False
    violence:
        description:
        - "Category Violence"
        required: False
    games:
        description:
        - "Category Games"
        required: False
    auctions:
        description:
        - "Category Auctions"
        required: False
    military:
        description:
        - "Category Military"
        required: False
    alcohol_and_tobacco:
        description:
        - "Category Alcohol and Tobacco"
        required: False
    stock_advice_and_tools:
        description:
        - "Category Stock Advice and Tools"
        required: False
    news_and_media:
        description:
        - "Category News and Media"
        required: False
    cult_and_occult:
        description:
        - "Category Cult and Occult"
        required: False
    food_and_dining:
        description:
        - "Category Food and Dining"
        required: False
    cheating:
        description:
        - "Category Cheating"
        required: False
    illegal:
        description:
        - "Category Illegal"
        required: False
    local_information:
        description:
        - "Category Local Information"
        required: False
    sports:
        description:
        - "Category Sports"
        required: False
    music:
        description:
        - "Category Music"
        required: False
    shareware_and_freeware:
        description:
        - "Category Shareware and Freeware"
        required: False
    spyware_and_adware:
        description:
        - "Category Spyware and Adware"
        required: False
    questionable:
        description:
        - "Category Questionable"
        required: False
    shopping:
        description:
        - "Category Shopping"
        required: False
    drugs:
        description:
        - "Category Abused Drugs"
        required: False
    web_hosting_sites:
        description:
        - "Category Web Hosting Sites"
        required: False
    malware_sites:
        description:
        - "Category Malware Sites"
        required: False
    dynamic_comment:
        description:
        - "Category Dynamic Comment"
        required: False
    translation:
        description:
        - "Category Translation"
        required: False
    job_search:
        description:
        - "Category Job Search"
        required: False
    hunting_and_fishing:
        description:
        - "Category Hunting and Fishing"
        required: False
    search_engines:
        description:
        - "Category Search Engines"
        required: False
    educational_institutions:
        description:
        - "Category Educational Institutions"
        required: False
    internet_portals:
        description:
        - "Category Internet Portals"
        required: False
    computer_and_internet_info:
        description:
        - "Category Computer and Internet Info"
        required: False
    abortion:
        description:
        - "Category Abortion"
        required: False
    hacking:
        description:
        - "Category Hacking"
        required: False
    adult_and_pornography:
        description:
        - "Category Adult and Pornography"
        required: False
    phishing_and_other_fraud:
        description:
        - "Category Phishing and Other Frauds"
        required: False
    nudity:
        description:
        - "Category Nudity"
        required: False
    health_and_medicine:
        description:
        - "Category Health and Medicine"
        required: False
    marijuana:
        description:
        - "Category Marijuana"
        required: False
    home_and_garden:
        description:
        - "Category Home and Garden"
        required: False
    personal_storage:
        description:
        - "Category Personal Storage"
        required: False
    sex_education:
        description:
        - "Category Sex Education"
        required: False
    swimsuits_and_intimate_apparel:
        description:
        - "Category Swimsuits and Intimate Apparel"
        required: False
    dead_sites:
        description:
        - "Category Dead Sites (db Ops only)"
        required: False
    travel:
        description:
        - "Category Travel"
        required: False
    hate_and_racism:
        description:
        - "Category Hate and Racism"
        required: False
    open_http_proxies:
        description:
        - "Category Open HTTP Proxies"
        required: False
    internet_communications:
        description:
        - "Category Internet Communications"
        required: False
    gambling:
        description:
        - "Category Gambling"
        required: False
    peer_to_peer:
        description:
        - "Category Peer to Peer"
        required: False
    uncategorized:
        description:
        - "Uncategorized URLs"
        required: False
    personal_sites_and_blogs:
        description:
        - "Category Personal sites and Blogs"
        required: False
    spam_urls:
        description:
        - "Category SPAM URLs"
        required: False
    unconfirmed_spam_sources:
        description:
        - "Category Unconfirmed SPAM Sources"
        required: False
    image_and_video_search:
        description:
        - "Category Image and Video Search"
        required: False
    training_and_tools:
        description:
        - "Category Training and Tools"
        required: False
    parked_domains:
        description:
        - "Category Parked Domains"
        required: False


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["abortion","adult_and_pornography","alcohol_and_tobacco","auctions","bot_nets","business_and_economy","cdns","cheating","computer_and_internet_info","computer_and_internet_security","confirmed_spam_sources","cult_and_occult","dating","dead_sites","drugs","dynamic_comment","educational_institutions","entertainment_and_arts","fashion_and_beauty","financial_services","food_and_dining","gambling","games","government","gross","hacking","hate_and_racism","health_and_medicine","home_and_garden","hunting_and_fishing","illegal","image_and_video_search","internet_communications","internet_portals","job_search","keyloggers_and_monitoring","kids","legal","local_information","malware_sites","marijuana","military","motor_vehicles","music","name","news_and_media","nudity","online_greeting_cards","open_http_proxies","parked_domains","pay_to_surf","peer_to_peer","personal_sites_and_blogs","personal_storage","philosophy_and_politics","phishing_and_other_fraud","private_ip_addresses","proxy_avoid_and_anonymizers","questionable","real_estate","recreation_and_hobbies","reference_and_research","religion","sampling_enable","search_engines","sex_education","shareware_and_freeware","shopping","social_network","society","spam_urls","sports","spyware_and_adware","stats","stock_advice_and_tools","streaming_media","swimsuits_and_intimate_apparel","training_and_tools","translation","travel","uncategorized","unconfirmed_spam_sources","user_tag","uuid","violence","weapons","web_advertisements","web_based_email","web_hosting_sites",]

# our imports go at the top so we fail fast.
try:
    from ansible_collections.a10.acos_axapi.plugins.module_utils import errors as a10_ex
    from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import client_factory, session_factory
    from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        streaming_media=dict(type='bool', ),
        weapons=dict(type='bool', ),
        uuid=dict(type='str', ),
        entertainment_and_arts=dict(type='bool', ),
        cdns=dict(type='bool', ),
        financial_services=dict(type='bool', ),
        social_network=dict(type='bool', ),
        government=dict(type='bool', ),
        web_advertisements=dict(type='bool', ),
        fashion_and_beauty=dict(type='bool', ),
        computer_and_internet_security=dict(type='bool', ),
        name=dict(type='str', required=True, ),
        real_estate=dict(type='bool', ),
        user_tag=dict(type='str', ),
        web_based_email=dict(type='bool', ),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'uncategorized', 'real-estate', 'computer-and-internet-security', 'financial-services', 'business-and-economy', 'computer-and-internet-info', 'auctions', 'shopping', 'cult-and-occult', 'travel', 'drugs', 'adult-and-pornography', 'home-and-garden', 'military', 'social-network', 'dead-sites', 'stock-advice-and-tools', 'training-and-tools', 'dating', 'sex-education', 'religion', 'entertainment-and-arts', 'personal-sites-and-blogs', 'legal', 'local-information', 'streaming-media', 'job-search', 'gambling', 'translation', 'reference-and-research', 'shareware-and-freeware', 'peer-to-peer', 'marijuana', 'hacking', 'games', 'philosophy-and-politics', 'weapons', 'pay-to-surf', 'hunting-and-fishing', 'society', 'educational-institutions', 'online-greeting-cards', 'sports', 'swimsuits-and-intimate-apparel', 'questionable', 'kids', 'hate-and-racism', 'personal-storage', 'violence', 'keyloggers-and-monitoring', 'search-engines', 'internet-portals', 'web-advertisements', 'cheating', 'gross', 'web-based-email', 'malware-sites', 'phishing-and-other-fraud', 'proxy-avoid-and-anonymizers', 'spyware-and-adware', 'music', 'government', 'nudity', 'news-and-media', 'illegal', 'CDNs', 'internet-communications', 'bot-nets', 'abortion', 'health-and-medicine', 'confirmed-SPAM-sources', 'SPAM-URLs', 'unconfirmed-SPAM-sources', 'open-HTTP-proxies', 'dynamic-comment', 'parked-domains', 'alcohol-and-tobacco', 'private-IP-addresses', 'image-and-video-search', 'fashion-and-beauty', 'recreation-and-hobbies', 'motor-vehicles', 'web-hosting-sites', 'food-and-dining'])),
        recreation_and_hobbies=dict(type='bool', ),
        business_and_economy=dict(type='bool', ),
        confirmed_spam_sources=dict(type='bool', ),
        philosophy_and_politics=dict(type='bool', ),
        society=dict(type='bool', ),
        motor_vehicles=dict(type='bool', ),
        proxy_avoid_and_anonymizers=dict(type='bool', ),
        gross=dict(type='bool', ),
        stats=dict(type='dict', philosophy_and_politics=dict(type='str', ), stock_advice_and_tools=dict(type='str', ), news_and_media=dict(type='str', ), business_and_economy=dict(type='str', ), peer_to_peer=dict(type='str', ), phishing_and_other_fraud=dict(type='str', ), nudity=dict(type='str', ), weapons=dict(type='str', ), CDNs=dict(type='str', ), marijuana=dict(type='str', ), home_and_garden=dict(type='str', ), cult_and_occult=dict(type='str', ), society=dict(type='str', ), unconfirmed_SPAM_sources=dict(type='str', ), personal_storage=dict(type='str', ), computer_and_internet_security=dict(type='str', ), food_and_dining=dict(type='str', ), motor_vehicles=dict(type='str', ), swimsuits_and_intimate_apparel=dict(type='str', ), dead_sites=dict(type='str', ), translation=dict(type='str', ), proxy_avoid_and_anonymizers=dict(type='str', ), financial_services=dict(type='str', ), gross=dict(type='str', ), cheating=dict(type='str', ), entertainment_and_arts=dict(type='str', ), sex_education=dict(type='str', ), illegal=dict(type='str', ), travel=dict(type='str', ), local_information=dict(type='str', ), legal=dict(type='str', ), sports=dict(type='str', ), bot_nets=dict(type='str', ), religion=dict(type='str', ), private_IP_addresses=dict(type='str', ), music=dict(type='str', ), hate_and_racism=dict(type='str', ), open_HTTP_proxies=dict(type='str', ), internet_communications=dict(type='str', ), shareware_and_freeware=dict(type='str', ), dating=dict(type='str', ), spyware_and_adware=dict(type='str', ), uncategorized=dict(type='str', ), questionable=dict(type='str', ), reference_and_research=dict(type='str', ), web_advertisements=dict(type='str', ), streaming_media=dict(type='str', ), social_network=dict(type='str', ), government=dict(type='str', ), drugs=dict(type='str', ), web_hosting_sites=dict(type='str', ), malware_sites=dict(type='str', ), name=dict(type='str', required=True, ), pay_to_surf=dict(type='str', ), kids=dict(type='str', ), gambling=dict(type='str', ), online_greeting_cards=dict(type='str', ), health_and_medicine=dict(type='str', ), SPAM_URLs=dict(type='str', ), image_and_video_search=dict(type='str', ), educational_institutions=dict(type='str', ), keyloggers_and_monitoring=dict(type='str', ), hunting_and_fishing=dict(type='str', ), search_engines=dict(type='str', ), fashion_and_beauty=dict(type='str', ), dynamic_comment=dict(type='str', ), computer_and_internet_info=dict(type='str', ), real_estate=dict(type='str', ), internet_portals=dict(type='str', ), shopping=dict(type='str', ), violence=dict(type='str', ), abortion=dict(type='str', ), hacking=dict(type='str', ), training_and_tools=dict(type='str', ), web_based_email=dict(type='str', ), personal_sites_and_blogs=dict(type='str', ), games=dict(type='str', ), parked_domains=dict(type='str', ), auctions=dict(type='str', ), job_search=dict(type='str', ), recreation_and_hobbies=dict(type='str', ), confirmed_SPAM_sources=dict(type='str', ), alcohol_and_tobacco=dict(type='str', ), adult_and_pornography=dict(type='str', ), military=dict(type='str', )),
        legal=dict(type='bool', ),
        bot_nets=dict(type='bool', ),
        religion=dict(type='bool', ),
        private_ip_addresses=dict(type='bool', ),
        dating=dict(type='bool', ),
        pay_to_surf=dict(type='bool', ),
        reference_and_research=dict(type='bool', ),
        keyloggers_and_monitoring=dict(type='bool', ),
        kids=dict(type='bool', ),
        online_greeting_cards=dict(type='bool', ),
        violence=dict(type='bool', ),
        games=dict(type='bool', ),
        auctions=dict(type='bool', ),
        military=dict(type='bool', ),
        alcohol_and_tobacco=dict(type='bool', ),
        stock_advice_and_tools=dict(type='bool', ),
        news_and_media=dict(type='bool', ),
        cult_and_occult=dict(type='bool', ),
        food_and_dining=dict(type='bool', ),
        cheating=dict(type='bool', ),
        illegal=dict(type='bool', ),
        local_information=dict(type='bool', ),
        sports=dict(type='bool', ),
        music=dict(type='bool', ),
        shareware_and_freeware=dict(type='bool', ),
        spyware_and_adware=dict(type='bool', ),
        questionable=dict(type='bool', ),
        shopping=dict(type='bool', ),
        drugs=dict(type='bool', ),
        web_hosting_sites=dict(type='bool', ),
        malware_sites=dict(type='bool', ),
        dynamic_comment=dict(type='bool', ),
        translation=dict(type='bool', ),
        job_search=dict(type='bool', ),
        hunting_and_fishing=dict(type='bool', ),
        search_engines=dict(type='bool', ),
        educational_institutions=dict(type='bool', ),
        internet_portals=dict(type='bool', ),
        computer_and_internet_info=dict(type='bool', ),
        abortion=dict(type='bool', ),
        hacking=dict(type='bool', ),
        adult_and_pornography=dict(type='bool', ),
        phishing_and_other_fraud=dict(type='bool', ),
        nudity=dict(type='bool', ),
        health_and_medicine=dict(type='bool', ),
        marijuana=dict(type='bool', ),
        home_and_garden=dict(type='bool', ),
        personal_storage=dict(type='bool', ),
        sex_education=dict(type='bool', ),
        swimsuits_and_intimate_apparel=dict(type='bool', ),
        dead_sites=dict(type='bool', ),
        travel=dict(type='bool', ),
        hate_and_racism=dict(type='bool', ),
        open_http_proxies=dict(type='bool', ),
        internet_communications=dict(type='bool', ),
        gambling=dict(type='bool', ),
        peer_to_peer=dict(type='bool', ),
        uncategorized=dict(type='bool', ),
        personal_sites_and_blogs=dict(type='bool', ),
        spam_urls=dict(type='bool', ),
        unconfirmed_spam_sources=dict(type='bool', ),
        image_and_video_search=dict(type='bool', ),
        training_and_tools=dict(type='bool', ),
        parked_domains=dict(type='bool', )
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/web-category/category-list/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)

def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"

def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k,v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module),
                                 params=query_params)
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")

def _build_dict_from_param(param):
    rv = {}

    for k,v in param.items():
        hk = _to_axapi(k)
        if isinstance(v, dict):
            v_dict = _build_dict_from_param(v)
            rv[hk] = v_dict
        elif isinstance(v, list):
            nv = [_build_dict_from_param(x) for x in v]
            rv[hk] = nv
        else:
            rv[hk] = v

    return rv

def build_envelope(title, data):
    return {
        title: data
    }

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/web-category/category-list/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if x in params and params.get(x) is not None])
    
    errors = []
    marg = []
    
    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc,msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc,msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc,msg = REQUIRED_VALID
    
    if not rc:
        errors.append(msg.format(", ".join(marg)))
    
    return rc,errors

def build_json(title, module):
    rv = {}

    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v is not None:
            rx = _to_axapi(x)

            if isinstance(v, dict):
                nv = _build_dict_from_param(v)
                rv[rx] = nv
            elif isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["category-list"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["category-list"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["category-list"][k] = v
            result.update(**existing_config)
    else:
        result.update(**payload)
    return result

def create(module, result, payload):
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def update(module, result, existing_config, payload):
    try:
        post_result = module.client.post(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def present(module, result, existing_config):
    payload = build_json("category-list", module)
    changed_config = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return changed_config
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and not changed_config.get('changed'):
        return update(module, result, existing_config, payload)
    else:
        result["changed"] = True
        return result

def delete(module, result):
    try:
        module.client.delete(existing_url(module))
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def absent(module, result, existing_config):
    if module.check_mode:
        if existing_config:
            result["changed"] = True
            return result
        else:
            result["changed"] = False
            return result
    else:
        return delete(module, result)

def replace(module, result, existing_config, payload):
    try:
        post_result = module.client.put(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def run_command(module):
    run_errors = []

    result = dict(
        changed=False,
        original_message="",
        message="",
        result={}
    )

    state = module.params["state"]
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    if ansible_port == 80:
        protocol = "http"
    elif ansible_port == 443:
        protocol = "https"

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)
    
    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)
    
    if state == 'present':
        result = present(module, result, existing_config)

    elif state == 'absent':
        result = absent(module, result, existing_config)
    
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    module.client.session.close()
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()