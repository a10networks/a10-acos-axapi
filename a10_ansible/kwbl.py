# (kw, translation)
# Storing it this way makes building dictionaries easy.
KW_BLACKLIST_TUPLES = [
    ("type", "ntype"),
    ("100_cont_wait_for_req_complete", "http_100_cont_wait_for_req_complete"),
    ("import", "nimport"),
    ("in", "nin"),
    ("exec", "nexec")
]

KW_IN = 0
KW_OUT = 1

KW_BLACKLIST = [{x[KW_IN]:x[KW_OUT] for x in KW_BLACKLIST_TUPLES}, 
                {x[KW_OUT]: x[KW_IN] for x in KW_BLACKLIST_TUPLES}]

def translate_blacklist(keyval, direction=KW_IN):
    return KW_BLACKLIST[direction].get(keyval, keyval)
