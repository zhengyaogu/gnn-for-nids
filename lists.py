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
"dns_query","dns_rcode","dns_AA","dns_RD","dns_rejected",
"ssl_resumed", "ssl_established",
"http_trans_depth","http_method","http_request_body_len","http_response_body_len", "http_status_code"
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