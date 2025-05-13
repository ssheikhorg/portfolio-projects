from facebook_business.api import FacebookAdsApi
from facebook_business.adobjects.adaccount import AdAccount
from facebook_business.adobjects.ad import Ad
from facebook_business.adobjects.adcreative import AdCreative
from facebook_business.adobjects.adset import AdSet
from dotenv import load_dotenv
from os import getenv

# Load credentials
load_dotenv()
PAGE_ID = getenv("FB_PAGE_ID")
USER_TOKEN = getenv("FB_USER_TOKEN")
AD_ACCOUNT_ID = getenv("AD_ACCOUNT_ID")

FacebookAdsApi.init(access_token=USER_TOKEN)
account = AdAccount(f"act_{AD_ACCOUNT_ID}")

# Create Campaign (Leads or Messenger)
campaign = account.create_campaign(
    params={
        "name": "Lead Gen and Messenger Ad Campaign",
        "objective": "LEAD_GENERATION",  # or "MESSAGE" for Messenger ads
        "status": "PAUSED",
        "special_ad_categories": [],
        "daily_budget": 2000,  # Example
    }
)

# Create Ad Set
adset = account.create_ad_set(
    params={
        "name": "Lead Gen and Messenger Ad Set",
        "campaign_id": campaign.get_id(),
        "status": "PAUSED",
        "billing_event": "IMPRESSIONS",
        "optimization_goal": "LEAD_GENERATION",  # or "MESSAGES" for Messenger ads
        "targeting": {
            "geo_locations": {"countries": ["US"]},
        },
        "promoted_object": {"page_id": PAGE_ID},
        "dynamic_creative": False,
    }
)

# Define text variations for Lead Gen and Messenger Ads
messages = [
    "Have questions about our services? Message us now!",
    "Get instant answers to your questions. Just send a message!",
    "Need help? Our team is ready to chat with you.",
    "Message us for personalized assistance with your needs.",
    "Quick responses guaranteed. Reach out to our team today!",
]

headlines = [
    "Chat With Us",
    "Message Our Team",
    "Get Answers Now",
    "Personalized Support",
    "Instant Assistance",
]

descriptions = [
    "We respond within minutes to all customer inquiries",
    "Our expert team is standing by to help you",
    "Fast and friendly service through Messenger",
    "No waiting on hold - just message us directly",
    "Connect with our specialists for immediate help",
]

# Prepare Ad Creative (use asset_feed_spec)
creative = account.create_ad_creative(
    params={
        "name": "Ad Creative with Multiple Text Variations",
        "object_story_spec": {
            "page_id": PAGE_ID,
            "link_data": {
                "message": messages,
                "name": headlines,
                "description": descriptions,
                "link": "https://m.me/" + PAGE_ID,  # For Messenger Ad
                "call_to_action": {"type": "MESSAGE_PAGE"},
            },
        },
        "asset_feed_spec": {
            "message": messages,
            "name": headlines,
            "description": descriptions,
            "image_hash": "your_image_hash_here",
            "link": "https://m.me/" + PAGE_ID,  # For Messenger Ad
        },
    }
)

# Create the Ad (PAUSED)
ad = account.create_ad(
    params={
        "name": "Lead Gen and Messenger Ad – Multiple Variations",
        "adset_id": adset.get_id(),
        "status": "PAUSED",
        "creative": {"creative_id": creative.get_id()},
    }
)

print("Campaign ID:", campaign.get_id())
print("Ad Set ID:", adset.get_id())
print("Ad ID:", ad.get_id())
print("Creative ID:", creative.get_id())
