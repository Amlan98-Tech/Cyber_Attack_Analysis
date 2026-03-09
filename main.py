import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

df=pd.read_csv("Data\cybersecurity_attacks.csv")
print(df)
print(df.head)

print(df.shape)
print(df.info())

print(df.describe)
print(df.columns)

print(df.isnull().sum())

print(df.columns)

df['Malware Indicators'] = df['Malware Indicators'].fillna("No Malware")

df['Alerts/Warnings'] = df['Alerts/Warnings'].fillna("No Alert")

df['Proxy Information'] = df['Proxy Information'].fillna("No Proxy")

df['Firewall Logs'] = df['Firewall Logs'].fillna("No Firewall Log")

df['IDS/IPS Alerts'] = df['IDS/IPS Alerts'].fillna("No IDS Alert")

print(df.isnull().sum())

df['Timestamp'] = pd.to_datetime(df['Timestamp'])
df['Year'] = df['Timestamp'].dt.year
df['Month'] = df['Timestamp'].dt.month
df['Hour'] = df['Timestamp'].dt.hour

print(df.columns)
print(df.info())
print(df.shape)

print(df.duplicated().sum())
df=df.drop_duplicates()
print(df.info())
print(df.shape)

attack_counts = df['Attack Type'].value_counts()

print(attack_counts)

print(df['Attack Type'].value_counts().head(10))

print(df['Protocol'].value_counts())

print(df['Network Segment'].value_counts())

print(df['Severity Level'].value_counts())

import numpy as np

print("Average Packet Length:", np.mean(df['Packet Length']))
print("Maximum Packet Length:", np.max(df['Packet Length']))
print("Minimum Packet Length:", np.min(df['Packet Length']))
print("Standard Deviation:", np.std(df['Packet Length']))

suspicious = df[df['Anomaly Scores'] > 80]

print(suspicious.head())

df['Attack Type'].value_counts().plot(kind='bar')

plt.title("Distribution of Cyber Attack Types")
plt.xlabel("Attack Type")
plt.ylabel("Count")

plt.show()

df['Protocol'].value_counts().plot(kind='bar')

plt.title("Network Protocol Usage")

plt.show()

df['Severity Level'].value_counts().plot(kind='bar')

plt.title("Attack Severity Levels")

plt.show()

df.groupby('Hour')['Attack Type'].count().plot(kind='line')

plt.title("Cyber Attacks by Hour")

plt.show()

plt.hist(df['Packet Length'], bins=30)

plt.title("Packet Length Distribution")

plt.xlabel("Packet Length")

plt.show()

df.to_csv("Data/cleaned_cyber_attacks.csv", index=False)