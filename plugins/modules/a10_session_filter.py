#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_session_filter
description:
    - Create a convenience Filter to display/clear sessions
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
    name:
        description:
        - "Session filter name"
        type: str
        required: True
    set:
        description:
        - "Set filter criteria"
        type: bool
        required: False
    filter_cfg:
        description:
        - "Field filter_cfg"
        type: dict
        required: False
        suboptions:
            session_type:
                description:
                - "'ipv6'= Display ipv6 sessions only; 'sip'= SIP sessions;"
                type: str
            source_addr:
                description:
                - "Forward Source IP (Source IP address)"
                type: str
            source_mask:
                description:
                - "Forward Source IP Subnet (Source Netmask)"
                type: str
            source_port:
                description:
                - "Forward Source Port"
                type: int
            dest_addr:
                description:
                - "Forward Destination IP (Destination IP address)"
                type: str
            dest_mask:
                description:
                - "Forward Destination IP Subnet (Destination Netmask)"
                type: str
            dport2:
                description:
                - "Forward Destination Port (Dest Port)"
                type: int
            app:
                description:
                - "Specify application(s), separated by comma (For example= http,tcp)"
                type: str
            app_category:
                description:
                - "'aaa'= Protocol/application used for AAA (Authentification, Authorization and
          Accounting) purposes.; 'adult-content'= Adult content protocol/application.;
          'advertising'= Advertising networks and applications.; 'application-enforcing-
          tls'= Application known to enforce HSTS and thus use of TLS.; 'analytics-and-
          statistics'= User analytics and statistics protocol/application.; 'anonymizers-
          and-proxies'= Traffic-anonymization protocol/application.; 'audio-chat'=
          Protocol/application used for Audio Chat.; 'basic'= Covers all protocols
          required for basic classification, including most networking protocols as well
          as standard protocols like HTTP.; 'blog'= Blogging platform
          protocol/application.; 'cdn'= Protocol/application used for Content-Delivery
          Networks.; 'certification-authority'= Certification Authority for SSL/TLS
          certificate.; 'chat'= Protocol/application used for Text Chat.; 'classified-
          ads'= Protocol/application used for Classified Advertisements.; 'cloud-based-
          services'= SaaS and/or PaaS cloud based services.; 'crowdfunding'= Service for
          funding a project or venture by raising small amounts of money from a large
          number of people, typically via the Internet.; 'cryptocurrency'= Services for
          mining cryptocurrencies, for example a Crypto Web Browser (an application that
          mines crypto currency in the background while its user browses the web).;
          'database'= Database-specific protocols.; 'disposable-email'= Service offering
          Disposable Email Accounts (DEA). DEA is a technique to share temporary email
          address between many users.; 'ebook-reader'= Services for e-book readers, i.e.
          connected devices that display electronic books (typically using e-ink displays
          to reduce glare and eye strain).; 'education'= Protocols offering education
          services and online courses.; 'email'= Native email protocol.; 'enterprise'=
          Protocol/application used in an enterprise network.; 'file-management'=
          Protocol/application designed specifically for file management and exchange.
          This can include bona fide network protocols (like SMB) as well as web/cloud
          services (like Dropbox).; 'file-transfer'= Protocol that offers file
          transferring as a secondary feature. This typically includes IM, WebMail, and
          other protocols that allow file transfers in addition to their principal
          function.; 'forum'= Online forum protocol/application.; 'gaming'=
          Protocol/application used by games.; 'healthcare'= Protocols offering medical
          services, i.e protocols used in medical environment.; 'instant-messaging-and-
          multimedia-conferencing'= Protocol/application used for Instant Messaging or
          Multi-Conferencing.; 'internet-of-things'= Internet Of Things
          protocol/application.; 'map-service'= Digital Maps service (web site and their
          related API).; 'mobile'= Mobile-specific protocol/application.; 'multimedia-
          streaming'= Protocol/application used for multimedia streaming.; 'networking'=
          Protocol used for (inter) networking purpose.; 'news-portal'=
          Protocol/application used for News Portals.; 'payment-service'= Application
          offering online services for accepting electronic payments by a variety of
          payment methods (credit card, bank-based payments such as direct debit, bank
          transfer, etc).; 'peer-to-peer'= Protocol/application used for Peer-to-peer
          purposes.; 'remote-access'= Protocol/application used for remote access.;
          'scada'= SCADA (Supervisory control and data acquisition) protocols, all
          generations.; 'social-networks'= Social networking application.; 'software-
          update'= Auto-update protocol.; 'speedtest'= Speedtest application allowing to
          access quality of Internet connection (upload, download, latency, etc).;
          'standards-based'= Protocol issued from standardized bodies such as IETF, ITU,
          IEEE, ETSI, OIF.; 'transportation'= Transportation services, for example
          smartphone applications that allow users to hail a taxi.; 'video-chat'=
          Protocol/application used for Video Chat.; 'voip'= Application used for Voice-
          Over-IP.; 'vpn-tunnels'= Protocol/application used for VPN or tunneling
          purposes.; 'web'= Application based on HTTP/HTTPS.; 'web-e-commerce'=
          Protocol/application used for E-commerce websites.; 'web-search-engines'=
          Protocol/application used for Web search portals.; 'web-websites'=
          Protocol/application used for Company Websites.; 'webmails'= Web-based e-mail
          application.; 'web-ext-adult'= Web Extension Adult; 'web-ext-auctions'= Web
          Extension Auctions; 'web-ext-blogs'= Web Extension Blogs; 'web-ext-business-
          and-economy'= Web Extension Business and Economy; 'web-ext-cdns'= Web Extension
          CDNs; 'web-ext-collaboration'= Web Extension Collaboration; 'web-ext-computer-
          and-internet-info'= Web Extension Computer and Internet Info; 'web-ext-
          computer-and-internet-security'= Web Extension Computer and Internet Security;
          'web-ext-dating'= Web Extension Dating; 'web-ext-educational-institutions'= Web
          Extension Educational Institutions; 'web-ext-entertainment-and-arts'= Web
          Extension Entertainment and Arts; 'web-ext-fashion-and-beauty'= Web Extension
          Fashion and Beauty; 'web-ext-file-share'= Web Extension File Share; 'web-ext-
          financial-services'= Web Extension Financial Services; 'web-ext-gambling'= Web
          Extension Gambling; 'web-ext-games'= Web Extension Games; 'web-ext-government'=
          Web Extension Government; 'web-ext-health-and-medicine'= Web Extension Health
          and Medicine; 'web-ext-individual-stock-advice-and-tools'= Web Extension
          Individual Stock Advice and Tools; 'web-ext-internet-portals'= Web Extension
          Internet Portals; 'web-ext-job-search'= Web Extension Job Search; 'web-ext-
          local-information'= Web Extension Local Information; 'web-ext-malware'= Web
          Extension Malware; 'web-ext-motor-vehicles'= Web Extension Motor Vehicles;
          'web-ext-music'= Web Extension Music; 'web-ext-news'= Web Extension News; 'web-
          ext-p2p'= Web Extension P2P; 'web-ext-parked-sites'= Web Extension Parked
          Sites; 'web-ext-proxy-avoid-and-anonymizers'= Web Extension Proxy Avoid and
          Anonymizers; 'web-ext-real-estate'= Web Extension Real Estate; 'web-ext-
          reference-and-research'= Web Extension Reference and Research; 'web-ext-search-
          engines'= Web Extension Search Engines; 'web-ext-shopping'= Web Extension
          Shopping; 'web-ext-social-network'= Web Extension Social Network; 'web-ext-
          society'= Web Extension Society; 'web-ext-software'= Web Extension Software;
          'web-ext-sports'= Web Extension Sports; 'web-ext-streaming-media'= Web
          Extension Streaming Media; 'web-ext-training-and-tools'= Web Extension Training
          and Tools; 'web-ext-translation'= Web Extension Translation; 'web-ext-travel'=
          Web Extension Travel; 'web-ext-web-advertisements'= Web Extension Web
          Advertisements; 'web-ext-web-based-email'= Web Extension Web based Email; 'web-
          ext-web-hosting'= Web Extension Web Hosting; 'web-ext-web-service'= Web
          Extension Web Service;"
                type: str
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False

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
AVAILABLE_PROPERTIES = ["filter_cfg", "name", "set", "uuid", ]


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
        'set': {
            'type': 'bool',
            },
        'filter_cfg': {
            'type': 'dict',
            'session_type': {
                'type': 'str',
                'choices': ['ipv6', 'sip']
                },
            'source_addr': {
                'type': 'str',
                },
            'source_mask': {
                'type': 'str',
                },
            'source_port': {
                'type': 'int',
                },
            'dest_addr': {
                'type': 'str',
                },
            'dest_mask': {
                'type': 'str',
                },
            'dport2': {
                'type': 'int',
                },
            'app': {
                'type': 'str',
                },
            'app_category': {
                'type':
                'str',
                'choices': [
                    'aaa', 'adult-content', 'advertising', 'application-enforcing-tls', 'analytics-and-statistics', 'anonymizers-and-proxies', 'audio-chat', 'basic', 'blog', 'cdn', 'certification-authority', 'chat', 'classified-ads', 'cloud-based-services', 'crowdfunding', 'cryptocurrency',
                    'database', 'disposable-email', 'ebook-reader', 'education', 'email', 'enterprise', 'file-management', 'file-transfer', 'forum', 'gaming', 'healthcare', 'instant-messaging-and-multimedia-conferencing', 'internet-of-things', 'map-service', 'mobile', 'multimedia-streaming',
                    'networking', 'news-portal', 'payment-service', 'peer-to-peer', 'remote-access', 'scada', 'social-networks', 'software-update', 'speedtest', 'standards-based', 'transportation', 'video-chat', 'voip', 'vpn-tunnels', 'web', 'web-e-commerce', 'web-search-engines', 'web-websites',
                    'webmails', 'web-ext-adult', 'web-ext-auctions', 'web-ext-blogs', 'web-ext-business-and-economy', 'web-ext-cdns', 'web-ext-collaboration', 'web-ext-computer-and-internet-info', 'web-ext-computer-and-internet-security', 'web-ext-dating', 'web-ext-educational-institutions',
                    'web-ext-entertainment-and-arts', 'web-ext-fashion-and-beauty', 'web-ext-file-share', 'web-ext-financial-services', 'web-ext-gambling', 'web-ext-games', 'web-ext-government', 'web-ext-health-and-medicine', 'web-ext-individual-stock-advice-and-tools', 'web-ext-internet-portals',
                    'web-ext-job-search', 'web-ext-local-information', 'web-ext-malware', 'web-ext-motor-vehicles', 'web-ext-music', 'web-ext-news', 'web-ext-p2p', 'web-ext-parked-sites', 'web-ext-proxy-avoid-and-anonymizers', 'web-ext-real-estate', 'web-ext-reference-and-research',
                    'web-ext-search-engines', 'web-ext-shopping', 'web-ext-social-network', 'web-ext-society', 'web-ext-software', 'web-ext-sports', 'web-ext-streaming-media', 'web-ext-training-and-tools', 'web-ext-translation', 'web-ext-travel', 'web-ext-web-advertisements',
                    'web-ext-web-based-email', 'web-ext-web-hosting', 'web-ext-web-service'
                    ]
                }
            },
        'uuid': {
            'type': 'str',
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/session-filter/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/session-filter/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["session-filter"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["session-filter"].get(k) != v:
            change_results["changed"] = True
            config_changes["session-filter"][k] = v

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
    payload = utils.build_json("session-filter", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["session-filter"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["session-filter-list"] if info != "NotFound" else info
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
