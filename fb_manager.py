import sys
from base64 import b64encode
from datetime import datetime, timedelta
from os import getenv

from dotenv import load_dotenv
from typing import Dict, List, Optional, Any

from facebook_business.adobjects.page import Page
from facebook_business.adobjects.user import User
from facebook_business.api import FacebookAdsApi
from facebook_business.adobjects.adaccount import AdAccount
from facebook_business.adobjects.lead import Lead
from facebook_business.exceptions import FacebookRequestError
from facebook_business.adobjects.adset import AdSet


class FacebookAdsBase:
    """Base class for Facebook Ads operations with shared functionality"""

    REQUIRED_CONFIG_KEYS = [
        "PAGE_ID",
        "USER_TOKEN",
        "AD_ACCOUNT_ID",
        "FB_APP_ID",
        "FB_APP_SECRET",
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
            "FB_APP_SECRET": getenv("FB_APP_SECRET"),
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
            access_token=self.config["USER_TOKEN"],
        )

    def get_ad_account(self) -> AdAccount:
        """Get the AdAccount instance"""
        return AdAccount(f"act_{self.config['AD_ACCOUNT_ID']}")

    def _get_page_access_token(self) -> str:
        """Retrieve page access token for the configured page"""
        user = User(f"me")
        accounts = user.get_accounts(fields=["access_token", "name", "id"])
        return next(
            (
                acc["access_token"]
                for acc in accounts
                if acc["id"] == self.config["PAGE_ID"]
            ),
            None,
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
                page_access_token,
            )

            since_date = (datetime.now() - timedelta(days=days_back)).strftime(
                "%Y-%m-%d"
            )
            page = Page(self.config["PAGE_ID"])
            forms = page.get_lead_gen_forms()

            leads_data = []
            for form in forms:
                leads = Lead(form["id"]).get_leads(params={"since": since_date})
                for lead in leads:
                    leads_data.append(
                        {
                            "id": lead["id"],
                            "created_time": lead["created_time"],
                            "form_name": form.get("name"),
                            "data": {
                                f["name"]: f["values"][0]
                                for f in lead.get("field_data", [])
                            },
                        }
                    )

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

    def _upload_image_file(
        self, account: AdAccount, image_path: str | None = None
    ) -> Dict[str, str]:
        if not image_path:
            image_path = "test-ad-img.jpeg"

        with open(image_path, "rb") as image_file:
            image_bytes = image_file.read()

        params = {
            "filename": image_path.split("/")[-1],
            "bytes": b64encode(image_bytes).decode("utf-8"),
        }
        image = account.create_ad_image(params=params)
        return {"hash": image["hash"], "url": image["url"], "id": image["id"]}

    def create_message_ad(self) -> Optional[Dict[str, str]]:
        """Create message engagement ad with multiple text variations"""
        try:
            account = self.get_ad_account()
            page_id = self.config["PAGE_ID"]

            campaign = self._create_campaign(account)
            campaign_id = campaign.get_id()
            adset = self._create_ad_set(account, campaign_id, page_id)
            creative = self._create_ad_creative(account, page_id)
            print("Variations:", creative.api_get(fields=["asset_feed_spec"]))

            ad = self._create_ad(account, adset.get_id(), creative.get_id())

            return {
                "campaign_id": campaign.get_id(),
                "adset_id": adset.get_id(),
                "ad_id": ad.get_id(),
                "creative_id": creative.get_id(),
            }
        except Exception as e:
            print(f"Error creating ad: {str(e)}")
            return None

    def _create_campaign(self, account: AdAccount) -> Any:
        """Create campaign optimized for lead generation"""
        return account.create_campaign(
            params={
                "name": "Lead Generation Campaign with Variations",
                "objective": "OUTCOME_LEADS",
                "status": "PAUSED",
                "special_ad_categories": [],
                "daily_budget": 2000,  # $20 daily budget
                "campaign_budget_optimization_toggling_behavior": "ENABLED",
            }
        )

    def _create_ad_set(self, account: AdAccount, campaign_id: str, page_id: str) -> Any:
        """Create lead gen ad set with proper budget structure"""
        targeting = {
            "geo_locations": {"countries": ["US", "GB"]},
            "age_min": 25,
            "age_max": 65,
            "publisher_platforms": ["facebook"],
            "facebook_positions": ["feed", "marketplace"],
            "locales": [6, 24],  # English (US/UK)
        }

        params = {
            "name": "Lead Gen AdSet with Variations",
            "campaign_id": campaign_id,
            "status": "PAUSED",
            "billing_event": "IMPRESSIONS",
            "optimization_goal": AdSet.OptimizationGoal.lead_generation,
            "bid_amount": "1000",  # $10 bid cap
            "targeting": targeting,
            "promoted_object": {"page_id": page_id},
            "dynamic_creative": True,
            "start_time": (datetime.now() + timedelta(days=1)).strftime(
                "%Y-%m-%dT%H:%M:%S"
            ),
            "end_time": (datetime.now() + timedelta(days=30)).strftime(
                "%Y-%m-%dT%H:%M:%S"
            ),
        }
        return account.create_ad_set(params=params)

    def _create_ad_creative(self, account: AdAccount, page_id: str) -> Any:
        """Create lead ad creative with multiple variations"""
        img = self._upload_image_file(account)

        # Variation sets (now as class constants for easy maintenance)
        MESSAGES = [
            "Get exclusive offers - sign up today!",
            "Limited time offer - claim your discount now",
            "We're hiring! Apply through this form",
            "Free consultation - get started today",
            "Download our premium guide instantly",
        ]
        HEADLINES = [
            "Chat With Us", "Message Our Team", "Get Answers Now",
            "Personalized Support", "Instant Assistance"
        ]
        DESCRIPTIONS = [
            "We respond within minutes to all customer inquiries",
            "Our expert team is standing by to help you",
            "Fast and friendly service through Messenger",
            "No waiting on hold - just message us directly",
            "Connect with our specialists for immediate help"
        ]

        creative_params = {
            "name": f"Lead Ad Variants {datetime.now().date()}",
            "object_story_spec": {
                "page_id": page_id,
                "lead_gen_data": {
                    "page_id": page_id,
                    "image_hash": img["hash"],
                    "title": HEADLINES[0],  # Use first headline as default
                    "message": MESSAGES[0],
                    "call_to_action": {"type": "SIGN_UP"},
                    "description": DESCRIPTIONS[0],
                },
            },
            "asset_feed_spec": {
                "ad_formats": ["SINGLE_IMAGE"],
                "bodies": [{"text": msg} for msg in MESSAGES],
                "headlines": [{"text": msg} for msg in HEADLINES],
                "descriptions": [{"text": msg} for msg in DESCRIPTIONS],
                "images": [{"hash": img["hash"]}],
                "call_to_action_types": ["SIGN_UP"],
            },
        }

        try:
            account.create_ad_creative(params={**creative_params, "validate_only": True})
            return account.create_ad_creative(params=creative_params)
        except FacebookRequestError as e:
            print(f"Creative creation failed: {e.api_error_message()}")
            raise

    def _create_ad(self, account: AdAccount, adset_id: str, creative_id: str) -> Any:
        """Create the final ad"""
        adset = AdSet(adset_id).api_get(fields=["status"])
        if adset["status"] != "PAUSED":
            print(f"Warning: AdSet status is {adset['status']}")

        return account.create_ad(
            params={
                "name": f"Lead Ad {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                "adset_id": adset_id,
                "status": "PAUSED",
                "creative": {"creative_id": creative_id},
                "access_token": self.config["USER_TOKEN"],
            }
        )


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
            for field, value in lead["data"].items():
                print(f"{field}: {value}")

    def create_and_display_message_ad(self) -> None:
        """Create and display message engagement ad"""

        print("\n2. Creating Message Engagement Ad...")
        ad_result = self.ad_creator.create_message_ad()
        if not ad_result:
            print("Ad creation failed.")
            return

        print("\nAd Creation Successful!")
        print("Campaign ID:", ad_result["campaign_id"])
        print("Ad Set ID:", ad_result["adset_id"])
        print("Ad ID:", ad_result["ad_id"])
        print("Creative ID:", ad_result["creative_id"])
        print("Check Ads Manager to see the five variations for each text field.")


def main():
    try:
        manager = FacebookAdsManager()

        # Retrieve and display leads
        manager.retrieve_and_display_leads()

        # Create and display message ad
        manager.create_and_display_message_ad()
    except ValueError as e:
        print(f"Configuration error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
