import pandas as pd
from url_features import extract_url_features

df = pd.read_csv("data/PhiUSIIL_Phishing_URL_Dataset.csv")

features = []

for url in df["URL"]:
    result = extract_url_features(url)
    features.append(result.iloc[0].to_dict())

new_df = pd.DataFrame(features)

new_df["Domain"] = df["Domain"]
new_df["label"] = df["label"]

new_df.to_csv("data/url_training_data.csv", index=False)

print("Training data created!")
print("Total URLs:", len(new_df))
print(new_df.head())