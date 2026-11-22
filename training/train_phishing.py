
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split, GroupShuffleSplit
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix


##loading datasets
df1 = pd.read_csv("data/Phishing_Email.csv")
df2 = pd.read_parquet("data/train.parquet")
df3 = pd.read_csv("data/PhiUSIIL_Phishing_URL_Dataset.csv")


#keeping necessary columns for table 1
df1 = df1[["Email Text", "Email Type"]].copy()

## removes missing and duplicate emails
df1 = df1.dropna(subset=["Email Text", "Email Type"])
df1 = df1.drop_duplicates(subset=["Email Text"])

##rename columns
df1 = df1.rename(columns={"Email Text": "text","Email Type": "label"})

## convert label  0 = safe, 1 = phishing
df1["label"] = df1["label"].map({"Safe Email": 0,"Phishing Email": 1})

# Check for invalid labels
assert df1["label"].notna().all(), "Invalid labels in Dataset 1!"

##Keep necessary columns and deletes missing values
df2_clean = df2[["text", "label", "dataset_name"]].copy()
df2_clean = df2_clean.dropna(subset=["text", "label"])

##removes extra spaces and empty emails
df2_clean["text"] = df2_clean["text"].str.strip()
df2_clean = df2_clean[df2_clean["text"] != ""]
#checks for conflicting email labels
conflicts = df2_clean.groupby("text")["label"].nunique()


assert (conflicts <= 1).all(), "Conflicting email labels found!"

## removes duplicate emails and saves cleaned dataset
df2_clean = df2_clean.drop_duplicates(subset=["text"]).copy()
df2_clean.to_csv("data/email_dataset2_clean.csv", index=False)


## makes a copy of dataset 3 and removes the FILENAME column
df3_clean = df3.copy()
df3_clean = df3_clean.drop(columns=["FILENAME"])

## remove missing URLs and labels and checks for conflicting URL labels
df3_clean = df3_clean.dropna(subset=["URL", "label"])
conflicts = df3_clean.groupby("URL")["label"].nunique()
assert (conflicts <= 1).all(), "Conflicting URL labels found!"

# Remove duplicate URLs and makes label 1 = safe, 0 = phishing
df3_clean = df3_clean.drop_duplicates(subset=["URL"]).copy()
df3_clean["label"] = 1 - df3_clean["label"]

## saves dataset 3
df3_clean.to_csv("data/url_dataset_clean.csv", index=False)

##inputs and labels for email model
X = df1["text"]
y = df1["label"]

## splitting email dataset into training and testing data
X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=0.2,random_state=42,stratify=y)

# Create TF-IDF and Logistic Regression pipeline
email_model = Pipeline([("tfidf", TfidfVectorizer(max_features=20000,ngram_range=(1, 2))),("classifier", LogisticRegression(max_iter=1000))])
email_model.fit(X_train, y_train)

## test email model and print classification report and confusion matrix
email_predictions = email_model.predict(X_test)
joblib.dump(email_model, "email_phishing_model.joblib")


# Select URL features
url_features = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "NoOfSubDomain",
    "NoOfLettersInURL",
    "NoOfDegitsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "IsHTTPS"]

# Inputs and labels
X_url = df3_clean[url_features]
y_url = df3_clean["label"]



# Keep URLs sharing the same exact domain together
splitter = GroupShuffleSplit(n_splits=1,test_size=0.2,random_state=42)

train_idx, test_idx = next(splitter.split(X_url,y_url,groups=df3_clean["Domain"]))

##selecting training and testing data for url model
X_url_train = X_url.iloc[train_idx]
X_url_test = X_url.iloc[test_idx]
y_url_train = y_url.iloc[train_idx]
y_url_test = y_url.iloc[test_idx]


# Create Random Forest classifier and fit the model
url_model = RandomForestClassifier(n_estimators=200,random_state=42,n_jobs=-1)
url_model.fit(X_url_train, y_url_train)
url_predictions = url_model.predict(X_url_test)

# Evaluate model
print("\nURL MODEL RESULTS:")
print(classification_report(y_url_test, url_predictions))
print(confusion_matrix(y_url_test, url_predictions))

##saving url model
joblib.dump(url_model, "url_phishing_model.joblib")
joblib.dump(url_features, "url_features.joblib")

print("URL model saved successfully!")
