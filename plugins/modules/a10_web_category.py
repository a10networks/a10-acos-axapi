#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_web_category
description:
    - Web-Category Commands
author: A10 Networks 2021
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
    server:
        description:
        - "BrightCloud Query Server"
        type: str
        required: False
    database_server:
        description:
        - "BrightCloud Database Server"
        type: str
        required: False
    port:
        description:
        - "BrightCloud Query Server Listening Port(default 80)"
        type: int
        required: False
    ssl_port:
        description:
        - "BrightCloud Servers SSL Port(default 443)"
        type: int
        required: False
    server_timeout:
        description:
        - "BrightCloud Servers Timeout in seconds (default= 15s)"
        type: int
        required: False
    cloud_query_disable:
        description:
        - "Disables cloud queries for URL's not present in local database(default enable)"
        type: bool
        required: False
    cloud_query_cache_size:
        description:
        - "Maximum cache size for storing cloud query results"
        type: int
        required: False
    db_update_time:
        description:
        - "Time of day to update database (default= 00=00)"
        type: str
        required: False
    rtu_update_disable:
        description:
        - "Disables real time updates(default enable)"
        type: bool
        required: False
    rtu_update_interval:
        description:
        - "Interval to check for real time updates if enabled in mins(default 60)"
        type: int
        required: False
    rtu_cache_size:
        description:
        - "Maximum cache size for storing RTU updates"
        type: int
        required: False
    use_mgmt_port:
        description:
        - "Use management interface for all communication with BrightCloud"
        type: bool
        required: False
    remote_syslog_enable:
        description:
        - "Enable data plane logging to a remote syslog server"
        type: bool
        required: False
    enable:
        description:
        - "Enable BrightCloud SDK"
        type: bool
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    proxy_server:
        description:
        - "Field proxy_server"
        type: dict
        required: False
        suboptions:
            proxy_host:
                description:
                - "Proxy server hostname or IP address"
                type: str
            http_port:
                description:
                - "Proxy server HTTP port"
                type: int
            https_port:
                description:
                - "Proxy server HTTPS port(HTTP port will be used if not configured)"
                type: int
            auth_type:
                description:
                - "'ntlm'= NTLM authentication(default); 'basic'= Basic authentication;"
                type: str
            domain:
                description:
                - "Realm for NTLM authentication"
                type: str
            username:
                description:
                - "Username for proxy authentication"
                type: str
            password:
                description:
                - "Password for proxy authentication"
                type: bool
            secret_string:
                description:
                - "password value"
                type: str
            encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED secret string)"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    intercepted_urls:
        description:
        - "Field intercepted_urls"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    bypassed_urls:
        description:
        - "Field bypassed_urls"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    url:
        description:
        - "Field url"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    license:
        description:
        - "Field license"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    category_list_list:
        description:
        - "Field category_list_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Web Category List name"
                type: str
            uncategorized:
                description:
                - "Uncategorized URLs"
                type: bool
            real_estate:
                description:
                - "Category Real Estate"
                type: bool
            computer_and_internet_security:
                description:
                - "Category Computer and Internet Security"
                type: bool
            financial_services:
                description:
                - "Category Financial Services"
                type: bool
            business_and_economy:
                description:
                - "Category Business and Economy"
                type: bool
            computer_and_internet_info:
                description:
                - "Category Computer and Internet Info"
                type: bool
            auctions:
                description:
                - "Category Auctions"
                type: bool
            shopping:
                description:
                - "Category Shopping"
                type: bool
            cult_and_occult:
                description:
                - "Category Cult and Occult"
                type: bool
            travel:
                description:
                - "Category Travel"
                type: bool
            drugs:
                description:
                - "Category Abused Drugs"
                type: bool
            adult_and_pornography:
                description:
                - "Category Adult and Pornography"
                type: bool
            home_and_garden:
                description:
                - "Category Home and Garden"
                type: bool
            military:
                description:
                - "Category Military"
                type: bool
            social_network:
                description:
                - "Category Social Network"
                type: bool
            dead_sites:
                description:
                - "Category Dead Sites (db Ops only)"
                type: bool
            stock_advice_and_tools:
                description:
                - "Category Stock Advice and Tools"
                type: bool
            training_and_tools:
                description:
                - "Category Training and Tools"
                type: bool
            dating:
                description:
                - "Category Dating"
                type: bool
            sex_education:
                description:
                - "Category Sex Education"
                type: bool
            religion:
                description:
                - "Category Religion"
                type: bool
            entertainment_and_arts:
                description:
                - "Category Entertainment and Arts"
                type: bool
            personal_sites_and_blogs:
                description:
                - "Category Personal sites and Blogs"
                type: bool
            legal:
                description:
                - "Category Legal"
                type: bool
            local_information:
                description:
                - "Category Local Information"
                type: bool
            streaming_media:
                description:
                - "Category Streaming Media"
                type: bool
            job_search:
                description:
                - "Category Job Search"
                type: bool
            gambling:
                description:
                - "Category Gambling"
                type: bool
            translation:
                description:
                - "Category Translation"
                type: bool
            reference_and_research:
                description:
                - "Category Reference and Research"
                type: bool
            shareware_and_freeware:
                description:
                - "Category Shareware and Freeware"
                type: bool
            peer_to_peer:
                description:
                - "Category Peer to Peer"
                type: bool
            marijuana:
                description:
                - "Category Marijuana"
                type: bool
            hacking:
                description:
                - "Category Hacking"
                type: bool
            games:
                description:
                - "Category Games"
                type: bool
            philosophy_and_politics:
                description:
                - "Category Philosophy and Political Advocacy"
                type: bool
            weapons:
                description:
                - "Category Weapons"
                type: bool
            pay_to_surf:
                description:
                - "Category Pay to Surf"
                type: bool
            hunting_and_fishing:
                description:
                - "Category Hunting and Fishing"
                type: bool
            society:
                description:
                - "Category Society"
                type: bool
            educational_institutions:
                description:
                - "Category Educational Institutions"
                type: bool
            online_greeting_cards:
                description:
                - "Category Online Greeting cards"
                type: bool
            sports:
                description:
                - "Category Sports"
                type: bool
            swimsuits_and_intimate_apparel:
                description:
                - "Category Swimsuits and Intimate Apparel"
                type: bool
            questionable:
                description:
                - "Category Questionable"
                type: bool
            kids:
                description:
                - "Category Kids"
                type: bool
            hate_and_racism:
                description:
                - "Category Hate and Racism"
                type: bool
            personal_storage:
                description:
                - "Category Personal Storage"
                type: bool
            violence:
                description:
                - "Category Violence"
                type: bool
            keyloggers_and_monitoring:
                description:
                - "Category Keyloggers and Monitoring"
                type: bool
            search_engines:
                description:
                - "Category Search Engines"
                type: bool
            internet_portals:
                description:
                - "Category Internet Portals"
                type: bool
            web_advertisements:
                description:
                - "Category Web Advertisements"
                type: bool
            cheating:
                description:
                - "Category Cheating"
                type: bool
            gross:
                description:
                - "Category Gross"
                type: bool
            web_based_email:
                description:
                - "Category Web based email"
                type: bool
            malware_sites:
                description:
                - "Category Malware Sites"
                type: bool
            phishing_and_other_fraud:
                description:
                - "Category Phishing and Other Frauds"
                type: bool
            proxy_avoid_and_anonymizers:
                description:
                - "Category Proxy Avoid and Anonymizers"
                type: bool
            spyware_and_adware:
                description:
                - "Category Spyware and Adware"
                type: bool
            music:
                description:
                - "Category Music"
                type: bool
            government:
                description:
                - "Category Government"
                type: bool
            nudity:
                description:
                - "Category Nudity"
                type: bool
            news_and_media:
                description:
                - "Category News and Media"
                type: bool
            illegal:
                description:
                - "Category Illegal"
                type: bool
            cdns:
                description:
                - "Category CDNs"
                type: bool
            internet_communications:
                description:
                - "Category Internet Communications"
                type: bool
            bot_nets:
                description:
                - "Category Bot Nets"
                type: bool
            abortion:
                description:
                - "Category Abortion"
                type: bool
            health_and_medicine:
                description:
                - "Category Health and Medicine"
                type: bool
            confirmed_spam_sources:
                description:
                - "Category Confirmed SPAM Sources"
                type: bool
            spam_urls:
                description:
                - "Category SPAM URLs"
                type: bool
            unconfirmed_spam_sources:
                description:
                - "Category Unconfirmed SPAM Sources"
                type: bool
            open_http_proxies:
                description:
                - "Category Open HTTP Proxies"
                type: bool
            dynamic_comment:
                description:
                - "Category Dynamic Comment"
                type: bool
            parked_domains:
                description:
                - "Category Parked Domains"
                type: bool
            alcohol_and_tobacco:
                description:
                - "Category Alcohol and Tobacco"
                type: bool
            private_ip_addresses:
                description:
                - "Category Private IP Addresses"
                type: bool
            image_and_video_search:
                description:
                - "Category Image and Video Search"
                type: bool
            fashion_and_beauty:
                description:
                - "Category Fashion and Beauty"
                type: bool
            recreation_and_hobbies:
                description:
                - "Category Recreation and Hobbies"
                type: bool
            motor_vehicles:
                description:
                - "Category Motor Vehicles"
                type: bool
            web_hosting_sites:
                description:
                - "Category Web Hosting Sites"
                type: bool
            food_and_dining:
                description:
                - "Category Food and Dining"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    statistics:
        description:
        - "Field statistics"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            web_cat_version:
                description:
                - "Field web_cat_version"
                type: str
            web_cat_database_name:
                description:
                - "Field web_cat_database_name"
                type: str
            web_cat_database_status:
                description:
                - "Field web_cat_database_status"
                type: str
            web_cat_database_size:
                description:
                - "Field web_cat_database_size"
                type: str
            web_cat_database_version:
                description:
                - "Field web_cat_database_version"
                type: int
            web_cat_last_update_time:
                description:
                - "Field web_cat_last_update_time"
                type: str
            web_cat_next_update_time:
                description:
                - "Field web_cat_next_update_time"
                type: str
            web_cat_connection_status:
                description:
                - "Field web_cat_connection_status"
                type: str
            web_cat_failure_reason:
                description:
                - "Field web_cat_failure_reason"
                type: str
            web_cat_last_successful_connection:
                description:
                - "Field web_cat_last_successful_connection"
                type: str
            intercepted_urls:
                description:
                - "Field intercepted_urls"
                type: dict
            bypassed_urls:
                description:
                - "Field bypassed_urls"
                type: dict
            url:
                description:
                - "Field url"
                type: dict
            license:
                description:
                - "Field license"
                type: dict
            statistics:
                description:
                - "Field statistics"
                type: dict

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
    "bypassed_urls",
    "category_list_list",
    "cloud_query_cache_size",
    "cloud_query_disable",
    "database_server",
    "db_update_time",
    "enable",
    "intercepted_urls",
    "license",
    "oper",
    "port",
    "proxy_server",
    "remote_syslog_enable",
    "rtu_cache_size",
    "rtu_update_disable",
    "rtu_update_interval",
    "server",
    "server_timeout",
    "ssl_port",
    "statistics",
    "url",
    "use_mgmt_port",
    "uuid",
]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str',
                   default="present",
                   choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(
            type='str',
            required=False,
        ),
        a10_device_context_id=dict(
            type='int',
            choices=[1, 2, 3, 4, 5, 6, 7, 8],
            required=False,
        ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'server': {
            'type': 'str',
        },
        'database_server': {
            'type': 'str',
        },
        'port': {
            'type': 'int',
        },
        'ssl_port': {
            'type': 'int',
        },
        'server_timeout': {
            'type': 'int',
        },
        'cloud_query_disable': {
            'type': 'bool',
        },
        'cloud_query_cache_size': {
            'type': 'int',
        },
        'db_update_time': {
            'type': 'str',
        },
        'rtu_update_disable': {
            'type': 'bool',
        },
        'rtu_update_interval': {
            'type': 'int',
        },
        'rtu_cache_size': {
            'type': 'int',
        },
        'use_mgmt_port': {
            'type': 'bool',
        },
        'remote_syslog_enable': {
            'type': 'bool',
        },
        'enable': {
            'type': 'bool',
        },
        'uuid': {
            'type': 'str',
        },
        'proxy_server': {
            'type': 'dict',
            'proxy_host': {
                'type': 'str',
            },
            'http_port': {
                'type': 'int',
            },
            'https_port': {
                'type': 'int',
            },
            'auth_type': {
                'type': 'str',
                'choices': ['ntlm', 'basic']
            },
            'domain': {
                'type': 'str',
            },
            'username': {
                'type': 'str',
            },
            'password': {
                'type': 'bool',
            },
            'secret_string': {
                'type': 'str',
            },
            'encrypted': {
                'type': 'str',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'intercepted_urls': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'bypassed_urls': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'url': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'license': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'category_list_list': {
            'type': 'list',
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
                        'all', 'uncategorized', 'real-estate',
                        'computer-and-internet-security', 'financial-services',
                        'business-and-economy', 'computer-and-internet-info',
                        'auctions', 'shopping', 'cult-and-occult', 'travel',
                        'drugs', 'adult-and-pornography', 'home-and-garden',
                        'military', 'social-network', 'dead-sites',
                        'stock-advice-and-tools', 'training-and-tools',
                        'dating', 'sex-education', 'religion',
                        'entertainment-and-arts', 'personal-sites-and-blogs',
                        'legal', 'local-information', 'streaming-media',
                        'job-search', 'gambling', 'translation',
                        'reference-and-research', 'shareware-and-freeware',
                        'peer-to-peer', 'marijuana', 'hacking', 'games',
                        'philosophy-and-politics', 'weapons', 'pay-to-surf',
                        'hunting-and-fishing', 'society',
                        'educational-institutions', 'online-greeting-cards',
                        'sports', 'swimsuits-and-intimate-apparel',
                        'questionable', 'kids', 'hate-and-racism',
                        'personal-storage', 'violence',
                        'keyloggers-and-monitoring', 'search-engines',
                        'internet-portals', 'web-advertisements', 'cheating',
                        'gross', 'web-based-email', 'malware-sites',
                        'phishing-and-other-fraud',
                        'proxy-avoid-and-anonymizers', 'spyware-and-adware',
                        'music', 'government', 'nudity', 'news-and-media',
                        'illegal', 'CDNs', 'internet-communications',
                        'bot-nets', 'abortion', 'health-and-medicine',
                        'confirmed-SPAM-sources', 'SPAM-URLs',
                        'unconfirmed-SPAM-sources', 'open-HTTP-proxies',
                        'dynamic-comment', 'parked-domains',
                        'alcohol-and-tobacco', 'private-IP-addresses',
                        'image-and-video-search', 'fashion-and-beauty',
                        'recreation-and-hobbies', 'motor-vehicles',
                        'web-hosting-sites', 'food-and-dining'
                    ]
                }
            }
        },
        'statistics': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'db-lookup', 'cloud-cache-lookup',
                        'cloud-lookup', 'rtu-lookup', 'lookup-latency',
                        'db-mem', 'rtu-cache-mem', 'lookup-cache-mem'
                    ]
                }
            }
        },
        'oper': {
            'type': 'dict',
            'web_cat_version': {
                'type': 'str',
            },
            'web_cat_database_name': {
                'type': 'str',
            },
            'web_cat_database_status': {
                'type': 'str',
            },
            'web_cat_database_size': {
                'type': 'str',
            },
            'web_cat_database_version': {
                'type': 'int',
            },
            'web_cat_last_update_time': {
                'type': 'str',
            },
            'web_cat_next_update_time': {
                'type': 'str',
            },
            'web_cat_connection_status': {
                'type': 'str',
            },
            'web_cat_failure_reason': {
                'type': 'str',
            },
            'web_cat_last_successful_connection': {
                'type': 'str',
            },
            'intercepted_urls': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'url_list': {
                        'type': 'list',
                        'url_name': {
                            'type': 'str',
                        }
                    },
                    'number_of_urls': {
                        'type': 'int',
                    },
                    'all_urls': {
                        'type': 'str',
                        'choices': ['true']
                    },
                    'url_name': {
                        'type': 'str',
                    }
                }
            },
            'bypassed_urls': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'url_list': {
                        'type': 'list',
                        'url_name': {
                            'type': 'str',
                        }
                    },
                    'number_of_urls': {
                        'type': 'int',
                    },
                    'all_urls': {
                        'type': 'str',
                        'choices': ['true']
                    },
                    'url_name': {
                        'type': 'str',
                    }
                }
            },
            'url': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'category_list': {
                        'type': 'list',
                        'category': {
                            'type': 'str',
                        }
                    },
                    'name': {
                        'type': 'str',
                    },
                    'local_db_only': {
                        'type': 'int',
                    }
                }
            },
            'license': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'module_status': {
                        'type': 'str',
                    },
                    'license_status': {
                        'type': 'str',
                    },
                    'license_type': {
                        'type': 'str',
                    },
                    'license_expiry': {
                        'type': 'str',
                    },
                    'remaining_period': {
                        'type': 'str',
                    },
                    'is_grace': {
                        'type': 'str',
                    },
                    'grace_period': {
                        'type': 'str',
                    },
                    'serial_number': {
                        'type': 'str',
                    }
                }
            },
            'statistics': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'num_dplane_threads': {
                        'type': 'int',
                    },
                    'num_lookup_threads': {
                        'type': 'int',
                    },
                    'per_cpu_list': {
                        'type': 'list',
                        'req_queue': {
                            'type': 'int',
                        },
                        'req_dropped': {
                            'type': 'int',
                        },
                        'req_processed': {
                            'type': 'int',
                        },
                        'req_lookup_processed': {
                            'type': 'int',
                        }
                    },
                    'total_req_queue': {
                        'type': 'int',
                    },
                    'total_req_dropped': {
                        'type': 'int',
                    },
                    'total_req_processed': {
                        'type': 'int',
                    },
                    'total_req_lookup_processed': {
                        'type': 'int',
                    }
                }
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/web-category"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/web-category"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["web-category"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["web-category"].get(k) != v:
            change_results["changed"] = True
            config_changes["web-category"][k] = v

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
    payload = utils.build_json("web-category", module.params,
                               AVAILABLE_PROPERTIES)
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
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[],
                  ansible_facts={},
                  acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params,
                                                  requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(
                api_client.switch_device_context(module.client,
                                                 a10_device_context_id))

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
                get_result = api_client.get(module.client,
                                            existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info[
                    "web-category"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "web-category-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client,
                                                      existing_url(module),
                                                      params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["web-category"][
                    "oper"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()
        raise gex
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
