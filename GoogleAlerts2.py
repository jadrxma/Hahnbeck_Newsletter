import streamlit as st
import feedparser
import openai
from datetime import datetime
import re

# Load OpenAI API key from Streamlit secrets
openai.api_key = st.secrets["OPENAI_API_KEY"]

# Hardcoded RSS Feed URLs
RSS_FEEDS = [
    "https://www.google.co.uk/alerts/feeds/00672085625077446626/7855545358850429722",
    "https://www.google.co.uk/alerts/feeds/00672085625077446626/12244836486553734503",
    "https://www.google.co.uk/alerts/feeds/00672085625077446626/13580635023242933218",
    "https://www.google.co.uk/alerts/feeds/00672085625077446626/6027728155530437398",
    "https://www.google.co.uk/alerts/feeds/00672085625077446626/12945809055854856130",
    "https://www.google.co.uk/alerts/feeds/00672085625077446626/16593091833703794172",
    "https://www.google.co.uk/alerts/feeds/00672085625077446626/5563357775526621570",
    "https://www.google.co.uk/alerts/feeds/00672085625077446626/8244803814714242935",
    "https://www.google.co.uk/alerts/feeds/00672085625077446626/2368405805161822986",
    "https://www.google.co.uk/alerts/feeds/00672085625077446626/2670728010081726541",
    "https://www.google.co.uk/alerts/feeds/00672085625077446626/7199575289154290510",
    "https://www.google.co.uk/alerts/feeds/00672085625077446626/5758220487720966515"
    
]
# Function to remove HTML tags
def clean_html(raw_html):
    cleanr = re.compile('<.*?>')
    return re.sub(cleanr, '', raw_html)

# Function to fetch Google Alerts
def fetch_google_alerts_rss(feed_urls):
    all_alerts = []
    for feed_url in feed_urls:
        try:
            feed = feedparser.parse(feed_url)
            for entry in feed.entries:
                alert = {
                    "title": clean_html(entry.title),
                    "link": entry.link,
                    "summary": clean_html(entry.get("summary", "")),
                    "published": entry.get("published", "No Date"),
                }
                all_alerts.append(alert)
        except Exception as e:
            st.error(f"Failed to fetch alerts from {feed_url}: {e}")
    return all_alerts

# Function to filter alerts related to acquisitions
def filter_acquisition_alerts(alerts):
    acquisition_keywords = ["acquisition", "acquires", "acquired", "merger", "buys"]
    acquisition_alerts = []

    for alert in alerts:
        if any(keyword in alert["title"].lower() or keyword in alert["summary"].lower() for keyword in acquisition_keywords):
            acquisition_alerts.append(alert)

    return acquisition_alerts

# Function to format acquisition alerts
def format_acquisition_alerts(alerts):
    categories = {}
    for alert in alerts:
        # Attempt to categorize based on keywords
        if "food" in alert["title"].lower() or "beverage" in alert["title"].lower():
            category = "Food and Beverages"
        elif "pet" in alert["title"].lower():
            category = "Pet Products"
        elif "beauty" in alert["title"].lower():
            category = "Beauty"
        elif "retail" in alert["title"].lower():
            category = "Retail"
        elif "electronics" in alert["title"].lower():
            category = "Electronics"
        elif "apparel" in alert["title"].lower():
            category = "Apparel"
        else:
            category = "Miscellaneous"

        if category not in categories:
            categories[category] = []

        categories[category].append(alert)

    formatted_output = f"**CPG Sector Acquisitions & News Update**\n{datetime.now().strftime('%d %B %Y')}\n\n"
    for category, items in categories.items():
        formatted_output += f"**{category}:**\n"
        for item in items:
            published_date = (
                datetime.strptime(item["published"], "%Y-%m-%dT%H:%M:%SZ").strftime("%d.%m.%Y")
                if "T" in item["published"]
                else item["published"]
            )
            # Include proper hyperlink for each article
            formatted_output += f"- {item['title']} ([link]({item['link']})) {published_date}\n"
        formatted_output += "\n"

    return formatted_output

# Function to summarize alerts using OpenAI (with categories and links)
def summarize_alerts_with_openai(alerts):
    try:
        # Combine alerts into a structured format with links for the prompt
        structured_alerts = "\n".join([f"- {alert['title']} ([link]({alert['link']}))" for alert in alerts])
        response = openai.ChatCompletion.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a helpful assistant that categorizes and summarizes acquisition-related news by industry."},
                {"role": "user", "content": f"Summarize and categorize the following acquisition-related alerts by industry and also include the sub-catergory as well such as (example: Hemp drinks: title and source) but include only health & wellness, food and beverages, sports and outdoors, home and DIY, Baby products and E-commerce focused brands, including links:\n\n{structured_alerts}"},
            ],
        )
        summary = response.choices[0].message["content"].strip()

        # Format the output with links
        formatted_summary = f"### OpenAI Summary\n\n{summary}\n\n---"
        return formatted_summary
    except Exception as e:
        st.error(f"Failed to summarize alerts with OpenAI: {e}")
        return ""

# Streamlit Layout
st.title("Google Alerts: Acquisitions Only")
st.write("Fetch, categorize, and summarize Google Alerts with a focus on acquisitions.")

# Fetch Alerts Button
if st.button("Fetch and Summarize Acquisitions"):
    with st.spinner("Fetching Google Alerts..."):
        alerts = fetch_google_alerts_rss(RSS_FEEDS)

    if alerts:
        with st.spinner("Filtering for acquisitions..."):
            acquisition_alerts = filter_acquisition_alerts(alerts)

        if acquisition_alerts:
            with st.spinner("Categorizing and formatting acquisitions..."):
                formatted_summary = format_acquisition_alerts(acquisition_alerts)

            # Display the formatted acquisition alerts
            st.subheader("Acquisition Updates")
            st.markdown(formatted_summary, unsafe_allow_html=True)

            # OpenAI Summarization
            with st.spinner("Generating summary...."):
                openai_summary = summarize_alerts_with_openai(acquisition_alerts)

            st.subheader("OpenAI Summary")
            st.markdown(openai_summary, unsafe_allow_html=True)
        else:
            st.warning("No acquisition-related alerts found.")
    else:
        st.warning("No alerts found. Please check your RSS feed URLs.")
