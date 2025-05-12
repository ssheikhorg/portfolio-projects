'''
def create_message_ad(account, page_id):
    """Create message engagement ad with multiple text variations"""
    try:
        # 1. Create Campaign with MESSAGES objective
        campaign = account.create_campaign(params={
            "name": "Message Engagement Campaign",
            "objective": "MESSAGES",  # Changed from OUTCOME_TRAFFIC
            "status": "PAUSED",
            "special_ad_categories": [],
            "daily_budget": 2000,  # cents (i.e. $20)
            "campaign_budget_optimization_toggling_behavior": "ENABLED",
        })
        print(f"Created Campaign {campaign.get_id()}")

        # 2. Create Ad Set with optimized parameters
        adset_params = {
            "name": "Message Engagement Ad Set",
            "campaign_id": campaign.get_id(),
            "status": "PAUSED",
            "daily_budget": "2000",  # Added at ad set level
            "billing_event": "IMPRESSIONS",  # Changed from LINK_CLICKS
            "optimization_goal": "REPLIES",  # Changed from LINK_CLICKS
            "bid_amount": "1000",  # cents ($10)
            "targeting": {
                "geo_locations": {"countries": ["US"]},
                "age_min": 25,
                "age_max": 65,
                "facebook_positions": ["feed"]  # Added explicit placement
            },
            "promoted_object": {"page_id": page_id},
            "messenger_welcome_message": "Thanks for contacting us! How can we help you today?",
            "dynamic_creative": True
        }

        # Only add advantage_audience if billing is active
        try:
            if account.get_billing_info().get('status') == 'ACTIVE':
                adset_params["advantage_audience"] = True
        except:
            pass  # Skip if we can't check billing status

        adset = account.create_ad_set(params=adset_params)
        print(f"Created Ad Set {adset.get_id()}")

        # 3. Prepare creative assets and text variations
        img = get_latest_image(account)

        messages = [
            "Have questions about our services? Message us now!",
            "Get instant answers to your questions. Just send a message!",
            "Need help? Our team is ready to chat with you.",
            "Message us for personalized assistance with your needs.",
            "Quick responses guaranteed. Reach out to our team today!",
        ]
        titles = [
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

        # 4. Create Ad Creative with multiple text variations
        creative = account.create_ad_creative(params={
            "name": "Message Engagement Creative - Multiple Text Options",
            "object_story_spec": {
                "page_id": page_id,
                "instagram_actor_id": page_id,  # For Instagram placement
                "link_data": {
                    "image_hash": img["hash"],
                    "link": "https://m.me/" + page_id,
                    "message": messages[0],
                    "name": titles[0],
                    "description": descriptions[0],
                    "call_to_action": {"type": "MESSAGE_PAGE"}
                }
            },
            "dynamic_creative_spec": {
                "message": messages,
                "link": ["https://m.me/" + page_id],
                "name": titles,
                "description": descriptions
            }
        })
        print(f"Created Ad Creative {creative.get_id()}")

        # 5. Create the Ad
        ad = account.create_ad(params={
            "name": "Message Engagement Ad - Multiple Text Variations",
            "adset_id": adset.get_id(),
            "status": "PAUSED",
            "creative": {"creative_id": creative.get_id()}
        })
        print(f"Created Ad {ad.get_id()}")

        return {
            "campaign_id": campaign.get_id(),
            "adset_id": adset.get_id(),
            "ad_id": ad.get_id(),
            "creative_id": creative.get_id()
        }

    except Exception as e:
        print(f"Error creating ad: {str(e)}")
        # Add detailed error logging for troubleshooting
        import traceback
        traceback.print_exc()
        return None
'''

import requests
from os import getenv

from dotenv import load_dotenv

load_dotenv()


def verify_token_permissions():
    token = getenv("FB_ACCESS_TOKEN")
    response = requests.get(
        f"https://graph.facebook.com/v19.0/me/permissions?access_token={token}"
    )
    if response.status_code == 200:
        print("Current permissions:")
        for perm in response.json()["data"]:
            print(f"{perm['permission']}: {perm['status']}")
    else:
        print("Error checking permissions:", response.json())


verify_token_permissions()
