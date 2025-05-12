import sys
from datetime import datetime, timedelta
from os import getenv
from dotenv import load_dotenv
from typing import Dict, List, Optional, Any

from facebook_business.adobjects.page import Page
from facebook_business.adobjects.user import User
from facebook_business.api import FacebookAdsApi
from facebook_business.adobjects.adaccount import AdAccount
from facebook_business.adobjects.ad import Ad
from facebook_business.adobjects.adcreative import AdCreative
from facebook_business.adobjects.adset import AdSet
from facebook_business.adobjects.lead import Lead
from facebook_business.exceptions import FacebookRequestError


class FacebookAdsBase:
    """Base class for Facebook Ads operations with shared functionality"""

    REQUIRED_CONFIG_KEYS = [
        "PAGE_ID",
        "USER_TOKEN",
        "AD_ACCOUNT_ID",
        "FB_APP_ID",
        "FB_APP_SECRET"
    ]

    def __init__(self, config: Optional[Dict[str, str]] = None):
        """Initialize with optional config, falls back to .env"""
        self.config = self._load_config(config)
        self._validate_config()
        self._init_api()

    def _load_config(self, config: Optional[Dict[str, str]]) -> Dict[str, str]:
        """Load configuration from dict or environment variables"""
        if config:
            return config

        load_dotenv()
        return {
            "PAGE_ID": getenv("FB_PAGE_ID"),
            "USER_TOKEN": getenv("FB_ACCESS_TOKEN"),
            "AD_ACCOUNT_ID": getenv("FB_AD_ACCOUNT_ID"),
            "FB_APP_ID": getenv("FB_APP_ID"),
            "FB_APP_SECRET": getenv("FB_APP_SECRET")
        }

    def _validate_config(self) -> None:
        """Validate that all required config values are present"""
        missing = [key for key in self.REQUIRED_CONFIG_KEYS if not self.config.get(key)]
        if missing:
            raise ValueError(f"Missing configuration for: {', '.join(missing)}")

    def _init_api(self) -> None:
        """Initialize the Facebook Ads API"""
        FacebookAdsApi.init(
            app_id=self.config["FB_APP_ID"],
            app_secret=self.config["FB_APP_SECRET"],
            access_token=self.config["USER_TOKEN"]
        )

    def get_ad_account(self) -> AdAccount:
        """Get the AdAccount instance"""
        return AdAccount(f"act_{self.config['AD_ACCOUNT_ID']}")

    def _get_page_access_token(self) -> str:
        """Retrieve page access token for the configured page"""
        user = User(f"me")
        accounts = user.get_accounts(fields=['access_token', 'name', 'id'])
        return next(
            (acc['access_token'] for acc in accounts if acc['id'] == self.config["PAGE_ID"]),
            None
        )


class FacebookLeadRetriever(FacebookAdsBase):
    """Handles retrieval of leads from Facebook lead gen forms"""

    def get_leads(self, days_back: int = 7) -> List[Dict[str, Any]]:
        """Retrieve leads from lead gen forms"""
        try:
            page_access_token = self._get_page_access_token()
            if not page_access_token:
                raise Exception("Could not get page access token")

            # Reinitialize with page token
            FacebookAdsApi.init(
                self.config["FB_APP_ID"],
                self.config["FB_APP_SECRET"],
                page_access_token
            )

            since_date = (datetime.now() - timedelta(days=days_back)).strftime('%Y-%m-%d')
            page = Page(self.config["PAGE_ID"])
            forms = page.get_lead_gen_forms()

            leads_data = []
            for form in forms:
                leads = Lead(form['id']).get_leads(params={'since': since_date})
                for lead in leads:
                    leads_data.append({
                        'id': lead['id'],
                        'created_time': lead['created_time'],
                        'form_name': form.get('name'),
                        'data': {f['name']: f['values'][0] for f in lead.get('field_data', [])}
                    })

            return leads_data

        except FacebookRequestError as e:
            print(f"Facebook API Error retrieving leads: {e.api_error_message()}")
            return []
        except Exception as e:
            print(f"Error retrieving leads: {str(e)}")
            return []


class FacebookAdCreator(FacebookAdsBase):
    """Handles creation of Facebook ads with various objectives"""

    def __init__(self, config: Optional[Dict[str, str]] = None):
        super().__init__(config)
        self._image_cache = None

    def get_latest_image(self) -> Dict[str, Any]:
        """Fetch most recent image in ad account with caching"""
        if self._image_cache:
            return self._image_cache

        fields = ["hash", "url", "created_time", "name"]
        account = self.get_ad_account()
        images = account.get_ad_images(fields=fields, params={"limit": 50})

        if not images:
            raise RuntimeError("No images found in the ad account - upload one first.")

        latest = max(images, key=lambda img: img.get("created_time", ""))
        print(f"Using image: {latest.get('name')} (hash={latest['hash']})")
        self._image_cache = latest
        return latest

    def create_message_ad(self) -> Optional[Dict[str, str]]:
        """Create message engagement ad with multiple text variations"""
        try:
            account = self.get_ad_account()
            page_id = self.config["PAGE_ID"]

            campaign = self._create_campaign(account)
            adset = self._create_ad_set(account, campaign.get_id(), page_id)
            creative = self._create_ad_creative(account, page_id)
            ad = self._create_ad(account, adset.get_id(), creative.get_id())

            return {
                "campaign_id": campaign.get_id(),
                "adset_id": adset.get_id(),
                "ad_id": ad.get_id(),
                "creative_id": creative.get_id()
            }

        except FacebookRequestError as e:
            print(f"Facebook API Error creating ad: {e.api_error_message()}")
            return None
        except Exception as e:
            print(f"Error creating ad: {str(e)}")
            return None

    def _create_campaign(self, account: AdAccount) -> Any:
        """Create campaign with MESSAGES objective"""
        return account.create_campaign(params={
            "name": "Message Engagement Campaign",
            "objective": "OUTCOME_TRAFFIC",
            "status": "PAUSED",
            "special_ad_categories": [],
            "daily_budget": 2000,
            "campaign_budget_optimization_toggling_behavior": "ENABLED",
        })

    def _create_ad_set(self, account: AdAccount, campaign_id: str, page_id: str) -> Any:
        """Create optimized ad set for message engagement"""
        adset_params = {
            "name": "Message Engagement Ad Set",
            "campaign_id": campaign_id,
            "status": "PAUSED",
            "daily_budget": "2000",
            "billing_event": "IMPRESSIONS",
            "optimization_goal": "REPLIES",
            "bid_amount": "1000",
            "targeting": {
                "geo_locations": {"countries": ["US"]},
                "age_min": 25,
                "age_max": 65,
                "facebook_positions": ["feed"]
            },
            "promoted_object": {"page_id": page_id},
            "messenger_welcome_message": "Thanks for contacting us! How can we help you today?",
            "dynamic_creative": True
        }

        try:
            if account.get_billing_info().get('status') == 'ACTIVE':
                adset_params["advantage_audience"] = True
        except:
            pass  # Skip if we can't check billing status

        return account.create_ad_set(params=adset_params)

    def _create_ad_creative(self, account: AdAccount, page_id: str) -> Any:
        """Create ad creative with multiple text variations"""
        img = self.get_latest_image()

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

        return account.create_ad_creative(params={
            "name": "Message Engagement Creative - Multiple Text Options",
            "object_story_spec": {
                "page_id": page_id,
                "instagram_actor_id": page_id,
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

    def _create_ad(self, account: AdAccount, adset_id: str, creative_id: str) -> Any:
        """Create the final ad"""
        return account.create_ad(params={
            "name": "Message Engagement Ad - Multiple Text Variations",
            "adset_id": adset_id,
            "status": "PAUSED",
            "creative": {"creative_id": creative_id}
        })


class FacebookAdsManager:
    """Main manager class that coordinates lead retrieval and ad creation"""

    def __init__(self, config: Optional[Dict[str, str]] = None):
        self.lead_retriever = FacebookLeadRetriever(config)
        self.ad_creator = FacebookAdCreator(config)

    def retrieve_and_display_leads(self, days_back: int = 7) -> None:
        """Retrieve and display leads from Facebook"""
        print("\n1. Retrieving Facebook Leads...")
        leads = self.lead_retriever.get_leads(days_back)
        print(f"Found {len(leads)} leads:")
        for lead in leads:
            print(f"\nLead ID: {lead['id']}")
            print(f"Date: {lead['created_time']}")
            for field, value in lead['data'].items():
                print(f"{field}: {value}")

    def create_and_display_message_ad(self) -> None:
        """Create and display message engagement ad"""
        print("\n2. Creating Message Engagement Ad...")
        ad_result = self.ad_creator.create_message_ad()
        if ad_result:
            print("\nAd Creation Successful!")
            print("Campaign ID:", ad_result["campaign_id"])
            print("Ad Set ID:", ad_result["adset_id"])
            print("Ad ID:", ad_result["ad_id"])
            print("Creative ID:", ad_result["creative_id"])
            print("Check Ads Manager to see the five variations for each text field.")
