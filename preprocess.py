import pandas as pd
import os
from tqdm import tqdm
import tldextract
from sklearn.preprocessing import LabelEncoder, OrdinalEncoder, MinMaxScaler, StandardScaler
from collections import defaultdict
from util import (
    in_majestic_million,
    user_agent_browser
)
import numpy as np
from lists import *
import pickle
import random


def prep_features(df, features_to_use,
                  ip_encoder,
                  label_encoder,
                  scalers_dict, 
                  categorical_lookups,
                  initial_transforms):
    """_summary_

    Args:
        df (pd.DataFrame): partition of data in a dataframe
        minmax_scalers_dict (Dict): a collection of dictionaries that correspond to each numeric column
        categorical_bounded_classes (Dict[str, int]): number of classes for each feature
        categorical_bounded_lookups (Dict[str, Dict[str, int]]):
        categorical_unbounded_transforms (Dict[str, Callable]):
    """

    # encode src & dst
    df.loc[:, "src"] = ip_encoder.transform(
        df.loc[:, "src"].values.reshape(-1, 1)
    ).astype(int)
    df.loc[df["src"] == -1, "src"] = len(ip_encoder.categories_[0])
    df.loc[:, "dst"] = ip_encoder.transform(
        df.loc[:, "dst"].values.reshape(-1, 1)
    ).astype(int)
    df.loc[df["dst"] == -1, "dst"] = len(ip_encoder.categories_[0])

    # add feature mask to dataframe
    for group in ["dns", "ssl", "http"]:
        indicator = group_to_indicator[group]
        idx = (df[indicator] != "-")
        df.loc[idx, group] = int(1)
        df.loc[~idx, group] = int(0)
    
    # perform initial transformation before encoding
    for att in initial_transforms:
        df.loc[:, att] = df[att].apply(
            initial_transforms[att]
        )
    
    # encode/scale features
    for feat in features_to_use:
        group = feature_groups_lookup[feat]
        att = (group, feat)
        if group == "shared":
            continue
        
        idx = (df[group_to_indicator[group]] != "-")
        
        if feature_type_lookup[feat].startswith("categorical"):
            lookup = categorical_lookups[feat]
            X = df[feat].values.reshape(-1, 1)
            if X.shape[0] > 0:
                df.loc[:, feat] = lookup.transform(
                    X
                )
                df.loc[df[feat] == -1, feat] = len(lookup.categories_[0])
        elif feature_type_lookup[feat] == "numeric":
            scaler = scalers_dict[feat]
            df.loc[~idx, feat] = 0.
            X = df[feat].values.reshape(-1, 1)
            if X.shape[0] > 0:
                df.loc[:, feat] = scaler.transform(
                    X
                )

    output_features = ["ts", "src", "dst"] + features_to_use + ["dns", "ssl", "http", "label", "type"]
    df = df.loc[:, output_features]
    df.loc[:, "type"] = label_encoder.transform(
        df["type"]
    )
    categorical_features = [
        feat for feat in features_to_use
        if feature_type_lookup[feat].startswith("categorical")
    ] + ["src", "dst", "label", "type"] + ["dns", "ssl", "http"]
    df = df.astype({
        feat: "int"
        for feat in categorical_features
    })
    return df

def combine_ip_port(df):
    df = df[~(
        df[("src_ip")].isna() |
        df[("src_port")].isna() |
        df[("dst_ip")].isna() |
        df[("dst_port")].isna()
    )]
    df[("src")] = df.apply(
        lambda s: str(s[("src_ip")]) + ":" + str(int(s[("src_port")])),
        axis=1
    )
    df[("dst")] = df.apply(
        lambda s: str(s[("dst_ip")]) + ":" + str(int(s[("dst_port")])),
        axis=1
    )
    df.drop(
        ["src_ip", "src_port", "dst_ip", "dst_port"],
        axis=1,
        inplace=True
    )

    return df


def preprocess(data_dir, features_to_use):
    """_summary_

    Args:
        data_dir (PathLike): data directory where the data partitions are
    """
    data_files = os.listdir(data_dir)

    initial_transforms = {
        "dns_query": in_majestic_million,
        "http_user_agent": user_agent_browser
    }
    
    categorical_lookups = {k: OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1) 
                                   for k in features_to_use 
                                   if feature_type_lookup[k] == "categorical_bounded"
                                   or feature_type_lookup[k] == "categorical_unbounded"}
    scalers_dict = {k: StandardScaler() for k in features_to_use if feature_type_lookup[k] == "numeric"}
    ips = set()
    ip_encoder = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
    label_encoder = LabelEncoder()


    train = pd.read_parquet(os.path.join(data_dir, "train.pq"))
    
    train = train[train.notna().all(axis=1)]
    train = combine_ip_port(train)
    ips.update(train["src"].unique().tolist())
    ips.update(train["dst"].unique().tolist())

    # perform initial transformation
    for att in initial_transforms:
        train.loc[:, att] = train[att].apply(
            initial_transforms[att]
        )
    print("starting to fit scalers/encoders")
    
    # firt scalers/encoders
    for att in features_to_use:
        group = feature_groups_lookup[att]
        exist_indicator = group_to_indicator[group]
        type = feature_type_lookup[att]
        if type == "categorical_bounded" or type == "categorical_unbounded":
            # categorical_bounded_sets[att].update(
            #     train[att].unique().tolist()
            # )
            categorical_lookups[att].fit(
                train[att].values.reshape(-1, 1)
            )
        elif type == "numeric":
            X = train[train[exist_indicator] != "-"][att].values.reshape(-1, 1)
            if X.shape[0] > 0:
                scalers_dict[att].partial_fit(X)
        
    ip_encoder = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)\
    .fit(
        np.array(list(ips)).reshape(-1, 1)
    )
    label_encoder = LabelEncoder().fit(
        train["type"].values.reshape(-1, 1)
    )

    with open(os.path.join("./data/ton_iot/processed", "transforms.pkl"), mode="wb") as f:
        pickle.dump({
            "categorical_bounded_lookups": categorical_lookups,
            "scalers_dict": scalers_dict,
            "ip_encoder": ip_encoder,
            "label_encoder": label_encoder
        }, f)
    
    for f in tqdm(data_files):
        df = pd.read_parquet(os.path.join(data_dir, f))
        df = df[df.notna().all(axis=1)]
        df = combine_ip_port(df)
        new_df = prep_features(
            df,
            features_to_use,
            ip_encoder,
            label_encoder,
            scalers_dict,
            categorical_lookups,
            initial_transforms
        )
        new_df.to_parquet(
            os.path.join("./data/ton_iot/processed", f)
        )

if __name__ == "__main__":
    data_dir = "./data/ton_iot/sample"
    preprocess(data_dir, features_to_use)