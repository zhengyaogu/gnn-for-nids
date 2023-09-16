#############################################################################
# features realted lists
#############################################################################
all_features = ['ts', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 'service',
       'duration', 'src_bytes', 'dst_bytes', 'conn_state', 'missed_bytes',
       'src_pkts', 'src_ip_bytes', 'dst_pkts', 'dst_ip_bytes', 'dns_query',
       'dns_qclass', 'dns_qtype', 'dns_rcode', 'dns_AA', 'dns_RD', 'dns_RA',
       'dns_rejected', 'ssl_version', 'ssl_cipher', 'ssl_resumed',
       'ssl_established', 'ssl_subject', 'ssl_issuer', 'http_trans_depth',
       'http_method', 'http_uri', 'http_version', 'http_request_body_len',
       'http_response_body_len', 'http_status_code', 'http_user_agent',
       'http_orig_mime_types', 'http_resp_mime_types', 'weird_name',
       'weird_addl', 'weird_notice', 'label', 'type']

features_to_use = [
"proto", "service", "duration","src_bytes","dst_bytes","conn_state","missed_bytes","src_pkts","src_ip_bytes","dst_pkts", "dst_ip_bytes",
"dns_query","dns_rcode","dns_AA","dns_RD","dns_rejected", "dns_qtype",
"ssl_resumed", "ssl_established",
"http_trans_depth","http_method","http_request_body_len","http_response_body_len", "http_status_code", "http_user_agent"
]

features_categorical_bounded = {
    "proto",
    "service",
    "conn_state",
    "dns_qclass",
    "dns_qtype",
    "dns_rcode",
    "dns_AA",
    "dns_RD",
    "dns_RA",
    "dns_rejected",
    "ssl_version",
    "ssl_cipher",
    "ssl_resumed",
    "ssl_established",
    "http_method",
    "http_version",
    "http_status_code",
    "http_user_agent",
    "http_orig_mime_types",
    "http_resp_mime_types",
    "weird_name",
    "weird_addl",
    "weird_notice", 
    "label", 
    "type"
}
features_categorical_unbounded = {
    "dns_query", 
    "ssl_subject",
    "ssl_issuer",
    "http_uri"
}
group_indicators = {
    "conn": "proto",
    "dns": "dns_query",
    "ssl": "ssl_version",
    "http": "http_uri"
}

def feature_to_type(k):
    if k in features_categorical_bounded:
        return "categorical_bounded"
    elif k in features_categorical_unbounded:
        return "categorical_unbounded"
    else:
        return "numeric"

def feature_group_locs(i):
    r = 0
    if i >= 5:
        r += 1
    if i >= 16:
        r += 1
    if i >= 24:
        r += 1
    if i >= 30:
        r += 1
    if i >= 40:
        r += 1
    if i >= 43:
        r += 1
    return r

feature_groups = ["shared", "conn", "dns", "ssl", "http", "weird", "label"]
feature_types = ["numeric", "categorical_bounded", "categorical_unbounded"]
feature_groups_lookup = {
    k: feature_groups[feature_group_locs(i)] for i, k in enumerate(all_features)
}
feature_type_lookup = {
    k: feature_to_type(k) for k in all_features
}

group_to_indicator = {
    "dns": "dns_query",
    "ssl": "ssl_version",
    "http": "http_uri",
    "conn": "proto"
}
