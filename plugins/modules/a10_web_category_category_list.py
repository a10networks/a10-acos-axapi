#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_web_category_category_list
description:
    - List of web categories
author: A10 Networks
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        type: str
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        type: str
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        type: str
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        type: str
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        type: int
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        type: int
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        type: str
        required: False
    name:
        description:
        - "Web Category List name"
        type: str
        required: True
    uncategorized:
        description:
        - "Uncategorized URLs"
        type: bool
        required: False
    real_estate:
        description:
        - "Category Real Estate"
        type: bool
        required: False
    computer_and_internet_security:
        description:
        - "Category Computer and Internet Security"
        type: bool
        required: False
    financial_services:
        description:
        - "Category Financial Services"
        type: bool
        required: False
    business_and_economy:
        description:
        - "Category Business and Economy"
        type: bool
        required: False
    computer_and_internet_info:
        description:
        - "Category Computer and Internet Info"
        type: bool
        required: False
    auctions:
        description:
        - "Category Auctions"
        type: bool
        required: False
    shopping:
        description:
        - "Category Shopping"
        type: bool
        required: False
    cult_and_occult:
        description:
        - "Category Cult and Occult"
        type: bool
        required: False
    travel:
        description:
        - "Category Travel"
        type: bool
        required: False
    drugs:
        description:
        - "Category Abused Drugs"
        type: bool
        required: False
    adult_and_pornography:
        description:
        - "Category Adult and Pornography"
        type: bool
        required: False
    home_and_garden:
        description:
        - "Category Home and Garden"
        type: bool
        required: False
    military:
        description:
        - "Category Military"
        type: bool
        required: False
    social_network:
        description:
        - "Category Social Network"
        type: bool
        required: False
    dead_sites:
        description:
        - "Category Dead Sites (db Ops only)"
        type: bool
        required: False
    stock_advice_and_tools:
        description:
        - "Category Stock Advice and Tools"
        type: bool
        required: False
    training_and_tools:
        description:
        - "Category Training and Tools"
        type: bool
        required: False
    dating:
        description:
        - "Category Dating"
        type: bool
        required: False
    sex_education:
        description:
        - "Category Sex Education"
        type: bool
        required: False
    religion:
        description:
        - "Category Religion"
        type: bool
        required: False
    entertainment_and_arts:
        description:
        - "Category Entertainment and Arts"
        type: bool
        required: False
    personal_sites_and_blogs:
        description:
        - "Category Personal sites and Blogs"
        type: bool
        required: False
    legal:
        description:
        - "Category Legal"
        type: bool
        required: False
    local_information:
        description:
        - "Category Local Information"
        type: bool
        required: False
    streaming_media:
        description:
        - "Category Streaming Media"
        type: bool
        required: False
    job_search:
        description:
        - "Category Job Search"
        type: bool
        required: False
    gambling:
        description:
        - "Category Gambling"
        type: bool
        required: False
    translation:
        description:
        - "Category Translation"
        type: bool
        required: False
    reference_and_research:
        description:
        - "Category Reference and Research"
        type: bool
        required: False
    shareware_and_freeware:
        description:
        - "Category Shareware and Freeware"
        type: bool
        required: False
    peer_to_peer:
        description:
        - "Category Peer to Peer"
        type: bool
        required: False
    marijuana:
        description:
        - "Category Marijuana"
        type: bool
        required: False
    hacking:
        description:
        - "Category Hacking"
        type: bool
        required: False
    games:
        description:
        - "Category Games"
        type: bool
        required: False
    philosophy_and_politics:
        description:
        - "Category Philosophy and Political Advocacy"
        type: bool
        required: False
    weapons:
        description:
        - "Category Weapons"
        type: bool
        required: False
    pay_to_surf:
        description:
        - "Category Pay to Surf"
        type: bool
        required: False
    hunting_and_fishing:
        description:
        - "Category Hunting and Fishing"
        type: bool
        required: False
    society:
        description:
        - "Category Society"
        type: bool
        required: False
    educational_institutions:
        description:
        - "Category Educational Institutions"
        type: bool
        required: False
    online_greeting_cards:
        description:
        - "Category Online Greeting cards"
        type: bool
        required: False
    sports:
        description:
        - "Category Sports"
        type: bool
        required: False
    swimsuits_and_intimate_apparel:
        description:
        - "Category Swimsuits and Intimate Apparel"
        type: bool
        required: False
    questionable:
        description:
        - "Category Questionable"
        type: bool
        required: False
    kids:
        description:
        - "Category Kids"
        type: bool
        required: False
    hate_and_racism:
        description:
        - "Category Hate and Racism"
        type: bool
        required: False
    personal_storage:
        description:
        - "Category Personal Storage"
        type: bool
        required: False
    violence:
        description:
        - "Category Violence"
        type: bool
        required: False
    keyloggers_and_monitoring:
        description:
        - "Category Keyloggers and Monitoring"
        type: bool
        required: False
    search_engines:
        description:
        - "Category Search Engines"
        type: bool
        required: False
    internet_portals:
        description:
        - "Category Internet Portals"
        type: bool
        required: False
    web_advertisements:
        description:
        - "Category Web Advertisements"
        type: bool
        required: False
    cheating:
        description:
        - "Category Cheating"
        type: bool
        required: False
    gross:
        description:
        - "Category Gross"
        type: bool
        required: False
    web_based_email:
        description:
        - "Category Web based email"
        type: bool
        required: False
    malware_sites:
        description:
        - "Category Malware Sites"
        type: bool
        required: False
    phishing_and_other_fraud:
        description:
        - "Category Phishing and Other Frauds"
        type: bool
        required: False
    proxy_avoid_and_anonymizers:
        description:
        - "Category Proxy Avoid and Anonymizers"
        type: bool
        required: False
    spyware_and_adware:
        description:
        - "Category Spyware and Adware"
        type: bool
        required: False
    music:
        description:
        - "Category Music"
        type: bool
        required: False
    government:
        description:
        - "Category Government"
        type: bool
        required: False
    nudity:
        description:
        - "Category Nudity"
        type: bool
        required: False
    news_and_media:
        description:
        - "Category News and Media"
        type: bool
        required: False
    illegal:
        description:
        - "Category Illegal"
        type: bool
        required: False
    cdns:
        description:
        - "Category CDNs"
        type: bool
        required: False
    internet_communications:
        description:
        - "Category Internet Communications"
        type: bool
        required: False
    bot_nets:
        description:
        - "Category Bot Nets"
        type: bool
        required: False
    abortion:
        description:
        - "Category Abortion"
        type: bool
        required: False
    health_and_medicine:
        description:
        - "Category Health and Medicine"
        type: bool
        required: False
    confirmed_spam_sources:
        description:
        - "Category Confirmed SPAM Sources"
        type: bool
        required: False
    spam_urls:
        description:
        - "Category SPAM URLs"
        type: bool
        required: False
    unconfirmed_spam_sources:
        description:
        - "Category Unconfirmed SPAM Sources"
        type: bool
        required: False
    open_http_proxies:
        description:
        - "Category Open HTTP Proxies"
        type: bool
        required: False
    dynamic_comment:
        description:
        - "Category Dynamic Comment"
        type: bool
        required: False
    dynamically_generated_content:
        description:
        - "Dynamically Generated Content"
        type: bool
        required: False
    parked_domains:
        description:
        - "Category Parked Domains"
        type: bool
        required: False
    alcohol_and_tobacco:
        description:
        - "Category Alcohol and Tobacco"
        type: bool
        required: False
    private_ip_addresses:
        description:
        - "Category Private IP Addresses"
        type: bool
        required: False
    image_and_video_search:
        description:
        - "Category Image and Video Search"
        type: bool
        required: False
    fashion_and_beauty:
        description:
        - "Category Fashion and Beauty"
        type: bool
        required: False
    recreation_and_hobbies:
        description:
        - "Category Recreation and Hobbies"
        type: bool
        required: False
    motor_vehicles:
        description:
        - "Category Motor Vehicles"
        type: bool
        required: False
    web_hosting_sites:
        description:
        - "Category Web Hosting Sites"
        type: bool
        required: False
    food_and_dining:
        description:
        - "Category Food and Dining"
        type: bool
        required: False
    nudity_artistic:
        description:
        - "Category Nudity join Entertainment and Arts"
        type: bool
        required: False
    illegal_pornography:
        description:
        - "Category Illegal join Adult and Pornography"
        type: bool
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    user_tag:
        description:
        - "Customized tag"
        type: str
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'uncategorized'= uncategorized category; 'real-estate'= real estate
          category; 'computer-and-internet-security'= computer and internet security
          category; 'financial-services'= financial services category; 'business-and-
          economy'= business and economy category; 'computer-and-internet-info'= computer
          and internet info category; 'auctions'= auctions category; 'shopping'= shopping
          category; 'cult-and-occult'= cult and occult category; 'travel'= travel
          category; 'drugs'= drugs category; 'adult-and-pornography'= adult and
          pornography category; 'home-and-garden'= home and garden category; 'military'=
          military category; 'social-network'= social network category; 'dead-sites'=
          dead sites category; 'stock-advice-and-tools'= stock advice and tools category;
          'training-and-tools'= training and tools category; 'dating'= dating category;
          'sex-education'= sex education category; 'religion'= religion category;
          'entertainment-and-arts'= entertainment and arts category; 'personal-sites-and-
          blogs'= personal sites and blogs category; 'legal'= legal category; 'local-
          information'= local information category; 'streaming-media'= streaming media
          category; 'job-search'= job search category; 'gambling'= gambling category;
          'translation'= translation category; 'reference-and-research'= reference and
          research category; 'shareware-and-freeware'= shareware and freeware category;
          'peer-to-peer'= peer to peer category; 'marijuana'= marijuana category;
          'hacking'= hacking category; 'games'= games category; 'philosophy-and-
          politics'= philosophy and politics category; 'weapons'= weapons category; 'pay-
          to-surf'= pay to surf category; 'hunting-and-fishing'= hunting and fishing
          category; 'society'= society category; 'educational-institutions'= educational
          institutions category; 'online-greeting-cards'= online greeting cards category;
          'sports'= sports category; 'swimsuits-and-intimate-apparel'= swimsuits and
          intimate apparel category; 'questionable'= questionable category; 'kids'= kids
          category; 'hate-and-racism'= hate and racism category; 'personal-storage'=
          personal storage category; 'violence'= violence category; 'keyloggers-and-
          monitoring'= keyloggers and monitoring category; 'search-engines'= search
          engines category; 'internet-portals'= internet portals category; 'web-
          advertisements'= web advertisements category; 'cheating'= cheating category;
          'gross'= gross category; 'web-based-email'= web based email category; 'malware-
          sites'= malware sites category; 'phishing-and-other-fraud'= phishing and other
          fraud category; 'proxy-avoid-and-anonymizers'= proxy avoid and anonymizers
          category; 'spyware-and-adware'= spyware and adware category; 'music'= music
          category; 'government'= government category; 'nudity'= nudity category; 'news-
          and-media'= news and media category; 'illegal'= illegal category; 'CDNs'=
          content delivery networks category; 'internet-communications'= internet
          communications category; 'bot-nets'= bot nets category; 'abortion'= abortion
          category; 'health-and-medicine'= health and medicine category; 'confirmed-SPAM-
          sources'= confirmed SPAM sources category; 'SPAM-URLs'= SPAM URLs category;
          'unconfirmed-SPAM-sources'= unconfirmed SPAM sources category; 'open-HTTP-
          proxies'= open HTTP proxies category; 'dynamically-generated-content'=
          dynamically generated content category; 'parked-domains'= parked domains
          category; 'alcohol-and-tobacco'= alcohol and tobacco category; 'private-IP-
          addresses'= private IP addresses category; 'image-and-video-search'= image and
          video search category; 'fashion-and-beauty'= fashion and beauty category;
          'recreation-and-hobbies'= recreation and hobbies category; 'motor-vehicles'=
          motor vehicles category; 'web-hosting-sites'= web hosting sites category;
          'food-and-dining'= food and dining category; 'nudity-artistic'= nudity join
          entertainment and arts; 'illegal-pornography'= illegal join adult and
          pornography;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            uncategorized:
                description:
                - "uncategorized category"
                type: str
            real_estate:
                description:
                - "real estate category"
                type: str
            computer_and_internet_security:
                description:
                - "computer and internet security category"
                type: str
            financial_services:
                description:
                - "financial services category"
                type: str
            business_and_economy:
                description:
                - "business and economy category"
                type: str
            computer_and_internet_info:
                description:
                - "computer and internet info category"
                type: str
            auctions:
                description:
                - "auctions category"
                type: str
            shopping:
                description:
                - "shopping category"
                type: str
            cult_and_occult:
                description:
                - "cult and occult category"
                type: str
            travel:
                description:
                - "travel category"
                type: str
            drugs:
                description:
                - "drugs category"
                type: str
            adult_and_pornography:
                description:
                - "adult and pornography category"
                type: str
            home_and_garden:
                description:
                - "home and garden category"
                type: str
            military:
                description:
                - "military category"
                type: str
            social_network:
                description:
                - "social network category"
                type: str
            dead_sites:
                description:
                - "dead sites category"
                type: str
            stock_advice_and_tools:
                description:
                - "stock advice and tools category"
                type: str
            training_and_tools:
                description:
                - "training and tools category"
                type: str
            dating:
                description:
                - "dating category"
                type: str
            sex_education:
                description:
                - "sex education category"
                type: str
            religion:
                description:
                - "religion category"
                type: str
            entertainment_and_arts:
                description:
                - "entertainment and arts category"
                type: str
            personal_sites_and_blogs:
                description:
                - "personal sites and blogs category"
                type: str
            legal:
                description:
                - "legal category"
                type: str
            local_information:
                description:
                - "local information category"
                type: str
            streaming_media:
                description:
                - "streaming media category"
                type: str
            job_search:
                description:
                - "job search category"
                type: str
            gambling:
                description:
                - "gambling category"
                type: str
            translation:
                description:
                - "translation category"
                type: str
            reference_and_research:
                description:
                - "reference and research category"
                type: str
            shareware_and_freeware:
                description:
                - "shareware and freeware category"
                type: str
            peer_to_peer:
                description:
                - "peer to peer category"
                type: str
            marijuana:
                description:
                - "marijuana category"
                type: str
            hacking:
                description:
                - "hacking category"
                type: str
            games:
                description:
                - "games category"
                type: str
            philosophy_and_politics:
                description:
                - "philosophy and politics category"
                type: str
            weapons:
                description:
                - "weapons category"
                type: str
            pay_to_surf:
                description:
                - "pay to surf category"
                type: str
            hunting_and_fishing:
                description:
                - "hunting and fishing category"
                type: str
            society:
                description:
                - "society category"
                type: str
            educational_institutions:
                description:
                - "educational institutions category"
                type: str
            online_greeting_cards:
                description:
                - "online greeting cards category"
                type: str
            sports:
                description:
                - "sports category"
                type: str
            swimsuits_and_intimate_apparel:
                description:
                - "swimsuits and intimate apparel category"
                type: str
            questionable:
                description:
                - "questionable category"
                type: str
            kids:
                description:
                - "kids category"
                type: str
            hate_and_racism:
                description:
                - "hate and racism category"
                type: str
            personal_storage:
                description:
                - "personal storage category"
                type: str
            violence:
                description:
                - "violence category"
                type: str
            keyloggers_and_monitoring:
                description:
                - "keyloggers and monitoring category"
                type: str
            search_engines:
                description:
                - "search engines category"
                type: str
            internet_portals:
                description:
                - "internet portals category"
                type: str
            web_advertisements:
                description:
                - "web advertisements category"
                type: str
            cheating:
                description:
                - "cheating category"
                type: str
            gross:
                description:
                - "gross category"
                type: str
            web_based_email:
                description:
                - "web based email category"
                type: str
            malware_sites:
                description:
                - "malware sites category"
                type: str
            phishing_and_other_fraud:
                description:
                - "phishing and other fraud category"
                type: str
            proxy_avoid_and_anonymizers:
                description:
                - "proxy avoid and anonymizers category"
                type: str
            spyware_and_adware:
                description:
                - "spyware and adware category"
                type: str
            music:
                description:
                - "music category"
                type: str
            government:
                description:
                - "government category"
                type: str
            nudity:
                description:
                - "nudity category"
                type: str
            news_and_media:
                description:
                - "news and media category"
                type: str
            illegal:
                description:
                - "illegal category"
                type: str
            CDNs:
                description:
                - "content delivery networks category"
                type: str
            internet_communications:
                description:
                - "internet communications category"
                type: str
            bot_nets:
                description:
                - "bot nets category"
                type: str
            abortion:
                description:
                - "abortion category"
                type: str
            health_and_medicine:
                description:
                - "health and medicine category"
                type: str
            confirmed_SPAM_sources:
                description:
                - "confirmed SPAM sources category"
                type: str
            SPAM_URLs:
                description:
                - "SPAM URLs category"
                type: str
            unconfirmed_SPAM_sources:
                description:
                - "unconfirmed SPAM sources category"
                type: str
            open_HTTP_proxies:
                description:
                - "open HTTP proxies category"
                type: str
            dynamically_generated_content:
                description:
                - "dynamically generated content category"
                type: str
            parked_domains:
                description:
                - "parked domains category"
                type: str
            alcohol_and_tobacco:
                description:
                - "alcohol and tobacco category"
                type: str
            private_IP_addresses:
                description:
                - "private IP addresses category"
                type: str
            image_and_video_search:
                description:
                - "image and video search category"
                type: str
            fashion_and_beauty:
                description:
                - "fashion and beauty category"
                type: str
            recreation_and_hobbies:
                description:
                - "recreation and hobbies category"
                type: str
            motor_vehicles:
                description:
                - "motor vehicles category"
                type: str
            web_hosting_sites:
                description:
                - "web hosting sites category"
                type: str
            food_and_dining:
                description:
                - "food and dining category"
                type: str
            nudity_artistic:
                description:
                - "nudity join entertainment and arts"
                type: str
            illegal_pornography:
                description:
                - "illegal join adult and pornography"
                type: str
            name:
                description:
                - "Web Category List name"
                type: str

'''

RETURN = r'''
modified_values:
    description:
    - Values modified (or potential changes if using check_mode) as a result of task operation
    returned: changed
    type: dict
axapi_calls:
    description: Sequential list of AXAPI calls made by the task
    returned: always
    type: list
    elements: dict
    contains:
        endpoint:
            description: The AXAPI endpoint being accessed.
            type: str
            sample:
                - /axapi/v3/slb/virtual_server
                - /axapi/v3/file/ssl-cert
        http_method:
            description:
            - HTTP method being used by the primary task to interact with the AXAPI endpoint.
            type: str
            sample:
                - POST
                - GET
        request_body:
            description: Params used to query the AXAPI
            type: complex
        response_body:
            description: Response from the AXAPI
            type: complex
'''

EXAMPLES = """
"""

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    wrapper as api_client
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    utils
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "abortion", "adult_and_pornography", "alcohol_and_tobacco", "auctions", "bot_nets", "business_and_economy", "cdns", "cheating", "computer_and_internet_info", "computer_and_internet_security", "confirmed_spam_sources", "cult_and_occult", "dating", "dead_sites", "drugs", "dynamic_comment", "dynamically_generated_content",
    "educational_institutions", "entertainment_and_arts", "fashion_and_beauty", "financial_services", "food_and_dining", "gambling", "games", "government", "gross", "hacking", "hate_and_racism", "health_and_medicine", "home_and_garden", "hunting_and_fishing", "illegal", "illegal_pornography", "image_and_video_search", "internet_communications",
    "internet_portals", "job_search", "keyloggers_and_monitoring", "kids", "legal", "local_information", "malware_sites", "marijuana", "military", "motor_vehicles", "music", "name", "news_and_media", "nudity", "nudity_artistic", "online_greeting_cards", "open_http_proxies", "parked_domains", "pay_to_surf", "peer_to_peer",
    "personal_sites_and_blogs", "personal_storage", "philosophy_and_politics", "phishing_and_other_fraud", "private_ip_addresses", "proxy_avoid_and_anonymizers", "questionable", "real_estate", "recreation_and_hobbies", "reference_and_research", "religion", "sampling_enable", "search_engines", "sex_education", "shareware_and_freeware", "shopping",
    "social_network", "society", "spam_urls", "sports", "spyware_and_adware", "stats", "stock_advice_and_tools", "streaming_media", "swimsuits_and_intimate_apparel", "training_and_tools", "translation", "travel", "uncategorized", "unconfirmed_spam_sources", "user_tag", "uuid", "violence", "weapons", "web_advertisements", "web_based_email",
    "web_hosting_sites",
    ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False,
                           ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False,
                                   ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
        )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'name': {
            'type': 'str',
            'required': True,
            },
        'uncategorized': {
            'type': 'bool',
            },
        'real_estate': {
            'type': 'bool',
            },
        'computer_and_internet_security': {
            'type': 'bool',
            },
        'financial_services': {
            'type': 'bool',
            },
        'business_and_economy': {
            'type': 'bool',
            },
        'computer_and_internet_info': {
            'type': 'bool',
            },
        'auctions': {
            'type': 'bool',
            },
        'shopping': {
            'type': 'bool',
            },
        'cult_and_occult': {
            'type': 'bool',
            },
        'travel': {
            'type': 'bool',
            },
        'drugs': {
            'type': 'bool',
            },
        'adult_and_pornography': {
            'type': 'bool',
            },
        'home_and_garden': {
            'type': 'bool',
            },
        'military': {
            'type': 'bool',
            },
        'social_network': {
            'type': 'bool',
            },
        'dead_sites': {
            'type': 'bool',
            },
        'stock_advice_and_tools': {
            'type': 'bool',
            },
        'training_and_tools': {
            'type': 'bool',
            },
        'dating': {
            'type': 'bool',
            },
        'sex_education': {
            'type': 'bool',
            },
        'religion': {
            'type': 'bool',
            },
        'entertainment_and_arts': {
            'type': 'bool',
            },
        'personal_sites_and_blogs': {
            'type': 'bool',
            },
        'legal': {
            'type': 'bool',
            },
        'local_information': {
            'type': 'bool',
            },
        'streaming_media': {
            'type': 'bool',
            },
        'job_search': {
            'type': 'bool',
            },
        'gambling': {
            'type': 'bool',
            },
        'translation': {
            'type': 'bool',
            },
        'reference_and_research': {
            'type': 'bool',
            },
        'shareware_and_freeware': {
            'type': 'bool',
            },
        'peer_to_peer': {
            'type': 'bool',
            },
        'marijuana': {
            'type': 'bool',
            },
        'hacking': {
            'type': 'bool',
            },
        'games': {
            'type': 'bool',
            },
        'philosophy_and_politics': {
            'type': 'bool',
            },
        'weapons': {
            'type': 'bool',
            },
        'pay_to_surf': {
            'type': 'bool',
            },
        'hunting_and_fishing': {
            'type': 'bool',
            },
        'society': {
            'type': 'bool',
            },
        'educational_institutions': {
            'type': 'bool',
            },
        'online_greeting_cards': {
            'type': 'bool',
            },
        'sports': {
            'type': 'bool',
            },
        'swimsuits_and_intimate_apparel': {
            'type': 'bool',
            },
        'questionable': {
            'type': 'bool',
            },
        'kids': {
            'type': 'bool',
            },
        'hate_and_racism': {
            'type': 'bool',
            },
        'personal_storage': {
            'type': 'bool',
            },
        'violence': {
            'type': 'bool',
            },
        'keyloggers_and_monitoring': {
            'type': 'bool',
            },
        'search_engines': {
            'type': 'bool',
            },
        'internet_portals': {
            'type': 'bool',
            },
        'web_advertisements': {
            'type': 'bool',
            },
        'cheating': {
            'type': 'bool',
            },
        'gross': {
            'type': 'bool',
            },
        'web_based_email': {
            'type': 'bool',
            },
        'malware_sites': {
            'type': 'bool',
            },
        'phishing_and_other_fraud': {
            'type': 'bool',
            },
        'proxy_avoid_and_anonymizers': {
            'type': 'bool',
            },
        'spyware_and_adware': {
            'type': 'bool',
            },
        'music': {
            'type': 'bool',
            },
        'government': {
            'type': 'bool',
            },
        'nudity': {
            'type': 'bool',
            },
        'news_and_media': {
            'type': 'bool',
            },
        'illegal': {
            'type': 'bool',
            },
        'cdns': {
            'type': 'bool',
            },
        'internet_communications': {
            'type': 'bool',
            },
        'bot_nets': {
            'type': 'bool',
            },
        'abortion': {
            'type': 'bool',
            },
        'health_and_medicine': {
            'type': 'bool',
            },
        'confirmed_spam_sources': {
            'type': 'bool',
            },
        'spam_urls': {
            'type': 'bool',
            },
        'unconfirmed_spam_sources': {
            'type': 'bool',
            },
        'open_http_proxies': {
            'type': 'bool',
            },
        'dynamic_comment': {
            'type': 'bool',
            },
        'dynamically_generated_content': {
            'type': 'bool',
            },
        'parked_domains': {
            'type': 'bool',
            },
        'alcohol_and_tobacco': {
            'type': 'bool',
            },
        'private_ip_addresses': {
            'type': 'bool',
            },
        'image_and_video_search': {
            'type': 'bool',
            },
        'fashion_and_beauty': {
            'type': 'bool',
            },
        'recreation_and_hobbies': {
            'type': 'bool',
            },
        'motor_vehicles': {
            'type': 'bool',
            },
        'web_hosting_sites': {
            'type': 'bool',
            },
        'food_and_dining': {
            'type': 'bool',
            },
        'nudity_artistic': {
            'type': 'bool',
            },
        'illegal_pornography': {
            'type': 'bool',
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'uncategorized', 'real-estate', 'computer-and-internet-security', 'financial-services', 'business-and-economy', 'computer-and-internet-info', 'auctions', 'shopping', 'cult-and-occult', 'travel', 'drugs', 'adult-and-pornography', 'home-and-garden', 'military', 'social-network', 'dead-sites', 'stock-advice-and-tools',
                    'training-and-tools', 'dating', 'sex-education', 'religion', 'entertainment-and-arts', 'personal-sites-and-blogs', 'legal', 'local-information', 'streaming-media', 'job-search', 'gambling', 'translation', 'reference-and-research', 'shareware-and-freeware', 'peer-to-peer', 'marijuana', 'hacking', 'games',
                    'philosophy-and-politics', 'weapons', 'pay-to-surf', 'hunting-and-fishing', 'society', 'educational-institutions', 'online-greeting-cards', 'sports', 'swimsuits-and-intimate-apparel', 'questionable', 'kids', 'hate-and-racism', 'personal-storage', 'violence', 'keyloggers-and-monitoring', 'search-engines', 'internet-portals',
                    'web-advertisements', 'cheating', 'gross', 'web-based-email', 'malware-sites', 'phishing-and-other-fraud', 'proxy-avoid-and-anonymizers', 'spyware-and-adware', 'music', 'government', 'nudity', 'news-and-media', 'illegal', 'CDNs', 'internet-communications', 'bot-nets', 'abortion', 'health-and-medicine', 'confirmed-SPAM-sources',
                    'SPAM-URLs', 'unconfirmed-SPAM-sources', 'open-HTTP-proxies', 'dynamically-generated-content', 'parked-domains', 'alcohol-and-tobacco', 'private-IP-addresses', 'image-and-video-search', 'fashion-and-beauty', 'recreation-and-hobbies', 'motor-vehicles', 'web-hosting-sites', 'food-and-dining', 'nudity-artistic',
                    'illegal-pornography'
                    ]
                }
            },
        'stats': {
            'type': 'dict',
            'uncategorized': {
                'type': 'str',
                },
            'real_estate': {
                'type': 'str',
                },
            'computer_and_internet_security': {
                'type': 'str',
                },
            'financial_services': {
                'type': 'str',
                },
            'business_and_economy': {
                'type': 'str',
                },
            'computer_and_internet_info': {
                'type': 'str',
                },
            'auctions': {
                'type': 'str',
                },
            'shopping': {
                'type': 'str',
                },
            'cult_and_occult': {
                'type': 'str',
                },
            'travel': {
                'type': 'str',
                },
            'drugs': {
                'type': 'str',
                },
            'adult_and_pornography': {
                'type': 'str',
                },
            'home_and_garden': {
                'type': 'str',
                },
            'military': {
                'type': 'str',
                },
            'social_network': {
                'type': 'str',
                },
            'dead_sites': {
                'type': 'str',
                },
            'stock_advice_and_tools': {
                'type': 'str',
                },
            'training_and_tools': {
                'type': 'str',
                },
            'dating': {
                'type': 'str',
                },
            'sex_education': {
                'type': 'str',
                },
            'religion': {
                'type': 'str',
                },
            'entertainment_and_arts': {
                'type': 'str',
                },
            'personal_sites_and_blogs': {
                'type': 'str',
                },
            'legal': {
                'type': 'str',
                },
            'local_information': {
                'type': 'str',
                },
            'streaming_media': {
                'type': 'str',
                },
            'job_search': {
                'type': 'str',
                },
            'gambling': {
                'type': 'str',
                },
            'translation': {
                'type': 'str',
                },
            'reference_and_research': {
                'type': 'str',
                },
            'shareware_and_freeware': {
                'type': 'str',
                },
            'peer_to_peer': {
                'type': 'str',
                },
            'marijuana': {
                'type': 'str',
                },
            'hacking': {
                'type': 'str',
                },
            'games': {
                'type': 'str',
                },
            'philosophy_and_politics': {
                'type': 'str',
                },
            'weapons': {
                'type': 'str',
                },
            'pay_to_surf': {
                'type': 'str',
                },
            'hunting_and_fishing': {
                'type': 'str',
                },
            'society': {
                'type': 'str',
                },
            'educational_institutions': {
                'type': 'str',
                },
            'online_greeting_cards': {
                'type': 'str',
                },
            'sports': {
                'type': 'str',
                },
            'swimsuits_and_intimate_apparel': {
                'type': 'str',
                },
            'questionable': {
                'type': 'str',
                },
            'kids': {
                'type': 'str',
                },
            'hate_and_racism': {
                'type': 'str',
                },
            'personal_storage': {
                'type': 'str',
                },
            'violence': {
                'type': 'str',
                },
            'keyloggers_and_monitoring': {
                'type': 'str',
                },
            'search_engines': {
                'type': 'str',
                },
            'internet_portals': {
                'type': 'str',
                },
            'web_advertisements': {
                'type': 'str',
                },
            'cheating': {
                'type': 'str',
                },
            'gross': {
                'type': 'str',
                },
            'web_based_email': {
                'type': 'str',
                },
            'malware_sites': {
                'type': 'str',
                },
            'phishing_and_other_fraud': {
                'type': 'str',
                },
            'proxy_avoid_and_anonymizers': {
                'type': 'str',
                },
            'spyware_and_adware': {
                'type': 'str',
                },
            'music': {
                'type': 'str',
                },
            'government': {
                'type': 'str',
                },
            'nudity': {
                'type': 'str',
                },
            'news_and_media': {
                'type': 'str',
                },
            'illegal': {
                'type': 'str',
                },
            'CDNs': {
                'type': 'str',
                },
            'internet_communications': {
                'type': 'str',
                },
            'bot_nets': {
                'type': 'str',
                },
            'abortion': {
                'type': 'str',
                },
            'health_and_medicine': {
                'type': 'str',
                },
            'confirmed_SPAM_sources': {
                'type': 'str',
                },
            'SPAM_URLs': {
                'type': 'str',
                },
            'unconfirmed_SPAM_sources': {
                'type': 'str',
                },
            'open_HTTP_proxies': {
                'type': 'str',
                },
            'dynamically_generated_content': {
                'type': 'str',
                },
            'parked_domains': {
                'type': 'str',
                },
            'alcohol_and_tobacco': {
                'type': 'str',
                },
            'private_IP_addresses': {
                'type': 'str',
                },
            'image_and_video_search': {
                'type': 'str',
                },
            'fashion_and_beauty': {
                'type': 'str',
                },
            'recreation_and_hobbies': {
                'type': 'str',
                },
            'motor_vehicles': {
                'type': 'str',
                },
            'web_hosting_sites': {
                'type': 'str',
                },
            'food_and_dining': {
                'type': 'str',
                },
            'nudity_artistic': {
                'type': 'str',
                },
            'illegal_pornography': {
                'type': 'str',
                },
            'name': {
                'type': 'str',
                'required': True,
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/web-category/category-list/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/web-category/category-list"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["category-list"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["category-list"].get(k) != v:
            change_results["changed"] = True
            config_changes["category-list"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(**call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("category-list", module.params, AVAILABLE_PROPERTIES)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


def delete(module, result):
    try:
        call_result = api_client.delete(module.client, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

    return delete(module, result)


def run_command(module):
    result = dict(changed=False, messages="", modified_values={}, axapi_calls=[], ansible_facts={}, acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params, requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(api_client.switch_device_context(module.client, a10_device_context_id))

        existing_config = api_client.get(module.client, existing_url(module))
        result["axapi_calls"].append(existing_config)
        if existing_config['response_body'] != 'NotFound':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["category-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["category-list-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["category-list"]["stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
