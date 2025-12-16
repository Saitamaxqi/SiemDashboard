import pandas as pd
df = pd.read_csv("training_data_ait.csv")
print(df["label"].value_counts())