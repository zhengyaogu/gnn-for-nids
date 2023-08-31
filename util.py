import tldextract
from lists import (
    features_categorical_bounded,
    features_categorical_unbounded
)

def dns_root(s):
    ex = tldextract.extract(s)
    return ".".join([ex.domain, ex.suffix])

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
    return r

def feature_to_type(k):
    if k in features_categorical_bounded:
        return "categorical_bounded"
    elif k in features_categorical_unbounded:
        return "categorical_unbounded"
    else:
        return "numeric"