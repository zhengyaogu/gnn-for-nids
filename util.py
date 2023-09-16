import tldextract
from random import randint
from lists import (
    features_categorical_bounded,
    features_categorical_unbounded
)
import socket
import struct
import user_agents as ua
import pandas as pd

majestic_million = set(pd.read_csv("./data/ton_iot/majestic_million.csv")["Domain"])

def random_ip():
    return socket.inet_ntoa(struct.pack('>I', randint(0xac100001, 0xac1f0001)))

def in_majestic_million(s):
    ex = tldextract.extract(s)
    root_domain = ".".join([ex.domain, ex.suffix])
    return str(root_domain in majestic_million) if s != "-" else "-"

def user_agent_browser(a):
    return ua.parse(a).browser.family if a != "-" else "-"