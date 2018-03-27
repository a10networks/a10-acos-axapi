#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_category-list
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - Web Category List name
    
    uncategorized:
        description:
            - Uncategorized URLs
    
    real-estate:
        description:
            - Category Real Estate
    
    computer-and-internet-security:
        description:
            - Category Computer and Internet Security
    
    financial-services:
        description:
            - Category Financial Services
    
    business-and-economy:
        description:
            - Category Business and Economy
    
    computer-and-internet-info:
        description:
            - Category Computer and Internet Info
    
    auctions:
        description:
            - Category Auctions
    
    shopping:
        description:
            - Category Shopping
    
    cult-and-occult:
        description:
            - Category Cult and Occult
    
    travel:
        description:
            - Category Travel
    
    drugs:
        description:
            - Category Abused Drugs
    
    adult-and-pornography:
        description:
            - Category Adult and Pornography
    
    home-and-garden:
        description:
            - Category Home and Garden
    
    military:
        description:
            - Category Military
    
    social-network:
        description:
            - Category Social Network
    
    dead-sites:
        description:
            - Category Dead Sites (db Ops only)
    
    stock-advice-and-tools:
        description:
            - Category Stock Advice and Tools
    
    training-and-tools:
        description:
            - Category Training and Tools
    
    dating:
        description:
            - Category Dating
    
    sex-education:
        description:
            - Category Sex Education
    
    religion:
        description:
            - Category Religion
    
    entertainment-and-arts:
        description:
            - Category Entertainment and Arts
    
    personal-sites-and-blogs:
        description:
            - Category Personal sites and Blogs
    
    legal:
        description:
            - Category Legal
    
    local-information:
        description:
            - Category Local Information
    
    streaming-media:
        description:
            - Category Streaming Media
    
    job-search:
        description:
            - Category Job Search
    
    gambling:
        description:
            - Category Gambling
    
    translation:
        description:
            - Category Translation
    
    reference-and-research:
        description:
            - Category Reference and Research
    
    shareware-and-freeware:
        description:
            - Category Shareware and Freeware
    
    peer-to-peer:
        description:
            - Category Peer to Peer
    
    marijuana:
        description:
            - Category Marijuana
    
    hacking:
        description:
            - Category Hacking
    
    games:
        description:
            - Category Games
    
    philosophy-and-politics:
        description:
            - Category Philosophy and Political Advocacy
    
    weapons:
        description:
            - Category Weapons
    
    pay-to-surf:
        description:
            - Category Pay to Surf
    
    hunting-and-fishing:
        description:
            - Category Hunting and Fishing
    
    society:
        description:
            - Category Society
    
    educational-institutions:
        description:
            - Category Educational Institutions
    
    online-greeting-cards:
        description:
            - Category Online Greeting cards
    
    sports:
        description:
            - Category Sports
    
    swimsuits-and-intimate-apparel:
        description:
            - Category Swimsuits and Intimate Apparel
    
    questionable:
        description:
            - Category Questionable
    
    kids:
        description:
            - Category Kids
    
    hate-and-racism:
        description:
            - Category Hate and Racism
    
    personal-storage:
        description:
            - Category Personal Storage
    
    violence:
        description:
            - Category Violence
    
    keyloggers-and-monitoring:
        description:
            - Category Keyloggers and Monitoring
    
    search-engines:
        description:
            - Category Search Engines
    
    internet-portals:
        description:
            - Category Internet Portals
    
    web-advertisements:
        description:
            - Category Web Advertisements
    
    cheating:
        description:
            - Category Cheating
    
    gross:
        description:
            - Category Gross
    
    web-based-email:
        description:
            - Category Web based email
    
    malware-sites:
        description:
            - Category Malware Sites
    
    phishing-and-other-fraud:
        description:
            - Category Phishing and Other Frauds
    
    proxy-avoid-and-anonymizers:
        description:
            - Category Proxy Avoid and Anonymizers
    
    spyware-and-adware:
        description:
            - Category Spyware and Adware
    
    music:
        description:
            - Category Music
    
    government:
        description:
            - Category Government
    
    nudity:
        description:
            - Category Nudity
    
    news-and-media:
        description:
            - Category News and Media
    
    illegal:
        description:
            - Category Illegal
    
    cdns:
        description:
            - Category CDNs
    
    internet-communications:
        description:
            - Category Internet Communications
    
    bot-nets:
        description:
            - Category Bot Nets
    
    abortion:
        description:
            - Category Abortion
    
    health-and-medicine:
        description:
            - Category Health and Medicine
    
    confirmed-spam-sources:
        description:
            - Category Confirmed SPAM Sources
    
    spam-urls:
        description:
            - Category SPAM URLs
    
    unconfirmed-spam-sources:
        description:
            - Category Unconfirmed SPAM Sources
    
    open-http-proxies:
        description:
            - Category Open HTTP Proxies
    
    dynamic-comment:
        description:
            - Category Dynamic Comment
    
    parked-domains:
        description:
            - Category Parked Domains
    
    alcohol-and-tobacco:
        description:
            - Category Alcohol and Tobacco
    
    private-ip-addresses:
        description:
            - Category Private IP Addresses
    
    image-and-video-search:
        description:
            - Category Image and Video Search
    
    fashion-and-beauty:
        description:
            - Category Fashion and Beauty
    
    recreation-and-hobbies:
        description:
            - Category Recreation and Hobbies
    
    motor-vehicles:
        description:
            - Category Motor Vehicles
    
    web-hosting-sites:
        description:
            - Category Web Hosting Sites
    
    food-and-dining:
        description:
            - Category Food and Dining
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    
    sampling-enable:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"abortion","adult_and_pornography","alcohol_and_tobacco","auctions","bot_nets","business_and_economy","cdns","cheating","computer_and_internet_info","computer_and_internet_security","confirmed_spam_sources","cult_and_occult","dating","dead_sites","drugs","dynamic_comment","educational_institutions","entertainment_and_arts","fashion_and_beauty","financial_services","food_and_dining","gambling","games","government","gross","hacking","hate_and_racism","health_and_medicine","home_and_garden","hunting_and_fishing","illegal","image_and_video_search","internet_communications","internet_portals","job_search","keyloggers_and_monitoring","kids","legal","local_information","malware_sites","marijuana","military","motor_vehicles","music","name","news_and_media","nudity","online_greeting_cards","open_http_proxies","parked_domains","pay_to_surf","peer_to_peer","personal_sites_and_blogs","personal_storage","philosophy_and_politics","phishing_and_other_fraud","private_ip_addresses","proxy_avoid_and_anonymizers","questionable","real_estate","recreation_and_hobbies","reference_and_research","religion","sampling_enable","search_engines","sex_education","shareware_and_freeware","shopping","social_network","society","spam_urls","sports","spyware_and_adware","stock_advice_and_tools","streaming_media","swimsuits_and_intimate_apparel","training_and_tools","translation","travel","uncategorized","unconfirmed_spam_sources","user_tag","uuid","violence","weapons","web_advertisements","web_based_email","web_hosting_sites",}

# our imports go at the top so we fail fast.
from a10_ansible.axapi_http import client_factory
from a10_ansible import errors as a10_ex

def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        
        abortion=dict(
            type='str' 
        ),
        adult_and_pornography=dict(
            type='str' 
        ),
        alcohol_and_tobacco=dict(
            type='str' 
        ),
        auctions=dict(
            type='str' 
        ),
        bot_nets=dict(
            type='str' 
        ),
        business_and_economy=dict(
            type='str' 
        ),
        cdns=dict(
            type='str' 
        ),
        cheating=dict(
            type='str' 
        ),
        computer_and_internet_info=dict(
            type='str' 
        ),
        computer_and_internet_security=dict(
            type='str' 
        ),
        confirmed_spam_sources=dict(
            type='str' 
        ),
        cult_and_occult=dict(
            type='str' 
        ),
        dating=dict(
            type='str' 
        ),
        dead_sites=dict(
            type='str' 
        ),
        drugs=dict(
            type='str' 
        ),
        dynamic_comment=dict(
            type='str' 
        ),
        educational_institutions=dict(
            type='str' 
        ),
        entertainment_and_arts=dict(
            type='str' 
        ),
        fashion_and_beauty=dict(
            type='str' 
        ),
        financial_services=dict(
            type='str' 
        ),
        food_and_dining=dict(
            type='str' 
        ),
        gambling=dict(
            type='str' 
        ),
        games=dict(
            type='str' 
        ),
        government=dict(
            type='str' 
        ),
        gross=dict(
            type='str' 
        ),
        hacking=dict(
            type='str' 
        ),
        hate_and_racism=dict(
            type='str' 
        ),
        health_and_medicine=dict(
            type='str' 
        ),
        home_and_garden=dict(
            type='str' 
        ),
        hunting_and_fishing=dict(
            type='str' 
        ),
        illegal=dict(
            type='str' 
        ),
        image_and_video_search=dict(
            type='str' 
        ),
        internet_communications=dict(
            type='str' 
        ),
        internet_portals=dict(
            type='str' 
        ),
        job_search=dict(
            type='str' 
        ),
        keyloggers_and_monitoring=dict(
            type='str' 
        ),
        kids=dict(
            type='str' 
        ),
        legal=dict(
            type='str' 
        ),
        local_information=dict(
            type='str' 
        ),
        malware_sites=dict(
            type='str' 
        ),
        marijuana=dict(
            type='str' 
        ),
        military=dict(
            type='str' 
        ),
        motor_vehicles=dict(
            type='str' 
        ),
        music=dict(
            type='str' 
        ),
        name=dict(
            type='str' , required=True
        ),
        news_and_media=dict(
            type='str' 
        ),
        nudity=dict(
            type='str' 
        ),
        online_greeting_cards=dict(
            type='str' 
        ),
        open_http_proxies=dict(
            type='str' 
        ),
        parked_domains=dict(
            type='str' 
        ),
        pay_to_surf=dict(
            type='str' 
        ),
        peer_to_peer=dict(
            type='str' 
        ),
        personal_sites_and_blogs=dict(
            type='str' 
        ),
        personal_storage=dict(
            type='str' 
        ),
        philosophy_and_politics=dict(
            type='str' 
        ),
        phishing_and_other_fraud=dict(
            type='str' 
        ),
        private_ip_addresses=dict(
            type='str' 
        ),
        proxy_avoid_and_anonymizers=dict(
            type='str' 
        ),
        questionable=dict(
            type='str' 
        ),
        real_estate=dict(
            type='str' 
        ),
        recreation_and_hobbies=dict(
            type='str' 
        ),
        reference_and_research=dict(
            type='str' 
        ),
        religion=dict(
            type='str' 
        ),
        sampling_enable=dict(
            type='str' 
        ),
        search_engines=dict(
            type='str' 
        ),
        sex_education=dict(
            type='str' 
        ),
        shareware_and_freeware=dict(
            type='str' 
        ),
        shopping=dict(
            type='str' 
        ),
        social_network=dict(
            type='str' 
        ),
        society=dict(
            type='str' 
        ),
        spam_urls=dict(
            type='str' 
        ),
        sports=dict(
            type='str' 
        ),
        spyware_and_adware=dict(
            type='str' 
        ),
        stock_advice_and_tools=dict(
            type='str' 
        ),
        streaming_media=dict(
            type='str' 
        ),
        swimsuits_and_intimate_apparel=dict(
            type='str' 
        ),
        training_and_tools=dict(
            type='str' 
        ),
        translation=dict(
            type='str' 
        ),
        travel=dict(
            type='str' 
        ),
        uncategorized=dict(
            type='str' 
        ),
        unconfirmed_spam_sources=dict(
            type='str' 
        ),
        user_tag=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ),
        violence=dict(
            type='str' 
        ),
        weapons=dict(
            type='str' 
        ),
        web_advertisements=dict(
            type='str' 
        ),
        web_based_email=dict(
            type='str' 
        ),
        web_hosting_sites=dict(
            type='str' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/web-category/category-list/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/web-category/category-list/{name}"
    f_dict = {}
    
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def build_envelope(title, data):
    return {
        title: data
    }

def build_json(title, module):
    rv = {}
    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v:
            rx = x.replace("_", "-")
            rv[rx] = module.params[x]

    return build_envelope(title, rv)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if params.get(x)])
    
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

def exists(module):
    try:
        module.client.get(existing_url(module))
        return True
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("category-list", module)
    try:
        post_result = module.client.post(new_url(module), payload)
        result.update(**post_result)
        result["changed"] = True
    except a10_ex.Exists:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
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

def update(module, result):
    payload = build_json("category-list", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
        result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def present(module, result):
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result)

def absent(module, result):
    return delete(module, result)



def run_command(module):
    run_errors = []

    result = dict(
        changed=False,
        original_message="",
        message=""
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    # TODO(remove hardcoded port #)
    a10_port = 443
    a10_protocol = "https"

    valid, validation_errors = validate(module.params)
    map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)

    if state == 'present':
        result = present(module, result)
    elif state == 'absent':
        result = absent(module, result)
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec())
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()