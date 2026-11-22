
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix


## converts spam csv into a dataframe 
##location of file
df = pd.read_csv("data/SMSSpamCollection/SMSSpamCollection",
    ##shows how the different items in the file are seperated by this one shows tab space
    sep="\t",
    #Marks that there are no headers
    header=None,
    #Creates the column names for dataframe
    names=["label", "message"]
)


##stores the cleaned dataset into a new dataframe
df = df.dropna(subset=["message", "label"])
df = df.drop_duplicates(subset=["message"])

##spam messages are stored as 1 and legitimate messages are stored as 0
df["label"] = df["label"].map({
    "ham": 0,
    "spam": 1
})

##reformats dataframe to remove empty rows from old commands
df = df.reset_index(drop=True)


# Separate the messages and their labels
X = df["message"]
y = df["label"]

# split into training 80% and testing 20%
X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=0.2,random_state=42,stratify=y)


model = Pipeline([("tfidf", TfidfVectorizer(lowercase=True,ngram_range=(1, 2))), ## converts text into a numeric representation using TF-IDF vectorization
    ("classifier", LogisticRegression(max_iter=1000,class_weight="balanced",random_state=42))])##goes through training data and learns patterns to classify messages as spam or not


model.fit(X_train, y_train)

# Predict labels for unseen test messages
## runs the model on test data to predict spam or not
y_pred = model.predict(X_test)

#prints the eport to check model performance
#checks performance of model using precision,detection and f1 score(balance between precision and detection)
print(classification_report(y_test,y_pred,target_names=["Legitimate", "Spam"]))

print("\nConfusion Matrix:")
#shows how many messages were correctly classified
print(confusion_matrix(y_test, y_pred))

from pathlib import Path

# Create a folder to store trained models
Path("models").mkdir(exist_ok=True)

# Save the trained model
joblib.dump(model, "models/sentinelai_spam_v1.joblib")

print("\nModel saved successfully!")