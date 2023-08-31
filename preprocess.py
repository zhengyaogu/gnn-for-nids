import pandas as pd
import os
from tqdm import tqdm
import tldextract
from sklearn.preprocessing import LabelEncoder, MinMaxScaler, StandardScaler
from collections import defaultdict
from util import dns_root, feature_group_locs, feature_to_type
import numpy as np
from lists import all_features, features_to_use

feature_groups = ["shared", "conn", "dns", "ssl", "http"]
feature_groups_lookup = {
    k: feature_groups[feature_group_locs(i)] for i, k in enumerate(all_features)
}
feature_type_lookup = {
    k: feature_to_type(k) for k in all_features
}


def prep_features(df, features_to_use,
                  scalers_dict, 
                  categorical_bounded_lookups,
                  categorical_unbounded_transforms):
    """_summary_

    Args:
        df (pd.DataFrame): partition of data in a dataframe
        minmax_scalers_dict (Dict): a collection of dictionaries that correspond to each numeric column
        categorical_bounded_classes (Dict[str, int]): number of classes for each feature
        categorical_bounded_lookups (Dict[str, Dict[str, int]]):
        categorical_unbounded_transforms (Dict[str, Callable]):
    """
    df[("shared", "src")] = df.apply(
        lambda s: s[("shared", "src_ip")] + ":" + str(s[("shared", "src_port")]),
        axis=1
    )
    df[("shared", "dst")] = df.apply(
        lambda s: s[("shared", "dst_ip")] + ":" + str(s[("shared", "dst_port")]),
        axis=1
    )
    df.drop(
        ["src_ip", "src_port", "dst_ip", "dst_port"],
        axis=1,
        level=1,
        inplace=True
    )
    
    for feat in features_to_use:
        group = feature_groups_lookup[feat]
        att = (group, feat)
        if group == "shared":
            continue
        
        if group == "dns":
            idx = (df[("dns", "dns_query")] != "-")
        elif group == "ssl":
            idx = (df[("ssl", "ssl_version")] != "-")
        elif group == "http":
            idx = (df[("http", "http_uri")] != "-")
        else:
            idx = (df[("conn", "proto")] != "-")
        
        if feature_type_lookup[feat] == "categorical_bounded":
            lookup = categorical_bounded_lookups[feat]
            X = df[idx][att].values
            if X.shape[0] > 0:
                df.loc[idx, (group, feat + "_transformed")] = lookup.transform(
                    df[idx][att].values
                )
        elif feature_type_lookup[feat] == "numeric":
            scaler = scalers_dict[feat]
            X = df[idx][att].values.reshape(-1, 1)
            if X.shape[0] > 0:
                df.loc[idx, (group, feat + "_transformed")] = scaler.transform(
                    X
                )
        else: # when the feature is unbounded
            transform = categorical_unbounded_transforms[feat]
            df.loc[idx, (group, feat + "_transformed")] = df[idx][att].apply(
                transform
            )

    return df


def preprocess(data_dir, features_to_use):
    """_summary_

    Args:
        data_dir (PathLike): data directory where the data partitions are
    """
    group_to_indicator = {
        "dns": "dns_query",
        "ssl": "ssl_version",
        "http": "http_uri",
        "conn": "proto"
    }
    data_files = os.listdir(data_dir)
    
    categorical_bounded_lookups = {k: LabelEncoder() for k in features_to_use if feature_type_lookup[k] == "categorical_bounded"}
    categorical_bounded_sets = defaultdict(set)
    scalers_dict = {k: StandardScaler() for k in features_to_use if feature_type_lookup[k] == "numeric"}
    
    for f in data_files:
        df = pd.read_csv(os.path.join(data_dir, f))
        for att in features_to_use:
            group = feature_groups_lookup[att]
            exist_indicator = group_to_indicator[group]
            type = feature_type_lookup[att]
            if type == "categorical_bounded":
                categorical_bounded_sets[att].update(
                    df[df[exist_indicator] != "-"][att].unique().tolist()
                )
            elif type == "numeric":
                X = df[df[exist_indicator] != "-"][att].values.reshape(-1, 1)
                if X.shape[0] > 0:
                    scalers_dict[att].partial_fit(X)
    categorical_bounded_lookups = {
        k: LabelEncoder().fit(np.array(list(s)).reshape(-1, 1))
        for k, s in categorical_bounded_sets.items()
    }
    
    print(categorical_bounded_lookups)
    print(scalers_dict)
    
    categorical_unbounded_transforms = {
        "dns_query": dns_root
    }
    
    for f in tqdm(data_files):
        df = pd.read_csv(os.path.join(data_dir, f))
        idx = pd.MultiIndex.from_tuples([
            (feature_groups_lookup[feature_name], feature_name) for feature_name in df.columns
        ])
        df.columns = idx

        new_df = prep_features(
            df,
            features_to_use,
            scalers_dict,
            categorical_bounded_lookups,
            categorical_unbounded_transforms
        )
        new_df.to_csv(
            os.path.join("./data/ton_iot/processed", f), 
            index=False,
            index_label=["group", "feature"]
        )

if __name__ == "__main__":
    data_dir = "./data/ton_iot/original"
    preprocess(data_dir, features_to_use)