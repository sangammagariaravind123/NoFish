import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

st.set_page_config(page_title="PhishTriage Demo", layout="wide")

st.title("🛡️ Phishing URL Detection – Hybrid Model + Rule Engine")

# Load data
df = pd.read_csv("phish_final_triage.csv")

# Sidebar filters
risk_filter = st.sidebar.multiselect("Filter by Risk Level", options=df['Risk_Level'].unique(), default=df['Risk_Level'].unique())
filtered_df = df[df['Risk_Level'].isin(risk_filter)]

# Metrics
st.metric("Total URLs", len(df))
st.metric("Safe URLs", len(df[df['Risk_Level']=='Safe']))
st.metric("Suspicious URLs", len(df[df['Risk_Level']=='Suspicious']))
st.metric("Phishing URLs", len(df[df['Risk_Level']=='Phishing']))

# Chart
st.subheader("Risk Distribution")
fig, ax = plt.subplots()
filtered_df['Risk_Level'].value_counts().plot(kind='bar', color=['limegreen','gold','tomato'], ax=ax)
st.pyplot(fig)

# Detailed table
st.subheader("Detailed Results")
st.dataframe(filtered_df[['url','Trust_Index','rule_score','Risk_Level','Triage_Explanation']])
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

st.set_page_config(page_title="PhishTriage Demo", layout="wide")

st.title("🛡️ Phishing URL Detection – Hybrid Model + Rule Engine")

# Load data
df = pd.read_csv("phish_final_triage.csv")

# Sidebar filters
risk_filter = st.sidebar.multiselect("Filter by Risk Level", options=df['Risk_Level'].unique(), default=df['Risk_Level'].unique())
filtered_df = df[df['Risk_Level'].isin(risk_filter)]

# Metrics
st.metric("Total URLs", len(df))
st.metric("Safe URLs", len(df[df['Risk_Level']=='Safe']))
st.metric("Suspicious URLs", len(df[df['Risk_Level']=='Suspicious']))
st.metric("Phishing URLs", len(df[df['Risk_Level']=='Phishing']))

# Chart
st.subheader("Risk Distribution")
fig, ax = plt.subplots()
filtered_df['Risk_Level'].value_counts().plot(kind='bar', color=['limegreen','gold','tomato'], ax=ax)
st.pyplot(fig)

# Detailed table
st.subheader("Detailed Results")
st.dataframe(filtered_df[['url','Trust_Index','rule_score','Risk_Level','Triage_Explanation']])
