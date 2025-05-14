import random
import sys
from base64 import b64encode
from datetime import datetime, timedelta
from os import getenv
from enum import Enum

from dotenv import load_dotenv
from typing import Optional, Any

from facebook_business.adobjects.page import Page
from facebook_business.adobjects.user import User
from facebook_business.api import FacebookAdsApi
from facebook_business.adobjects.adaccount import AdAccount
from facebook_business.exceptions import FacebookRequestError
from facebook_business.adobjects.adset import AdSet
from facebook_business.adobjects.leadgenform import LeadgenForm


class AdTypeEnum(Enum):
    """Enum for ad types"""

    LEAD = "lead"
    MESSAGE = "message"


class FacebookAdsManager:
    """Base class for Facebook Ads operations with shared functionality"""

    REQUIRED_CONFIG_KEYS = [
        "PAGE_ID",
        "USER_TOKEN",
        "AD_ACCOUNT_ID",
        "FB_APP_ID",
        "FB_APP_SECRET",
    ]

    def __init__(self):
        """Initialize with optional config, falls back to .env"""
        self.config = self.loadConfig()
        self.validateConfig()
        self.initApi()
        self.account = self.initAccount()  # Initialize account on startup

    def loadConfig(self) -> dict[str, str]:
        """Load configuration from dict or environment variables"""
        load_dotenv()
        return {
            "PAGE_ID": getenv("FB_PAGE_ID"),
            "USER_TOKEN": getenv("FB_ACCESS_TOKEN"),
            "AD_ACCOUNT_ID": getenv("FB_AD_ACCOUNT_ID"),
            "FB_APP_ID": getenv("FB_APP_ID"),
            "FB_APP_SECRET": getenv("FB_APP_SECRET"),
        }

    def validateConfig(self) -> None:
        """Validate that all required config values are present"""
        missing = [key for key in self.REQUIRED_CONFIG_KEYS if not self.config.get(key)]
        if missing:
            raise ValueError(f"Missing configuration for: {', '.join(missing)}")

    def initApi(self) -> None:
        """Initialize the Facebook Ads API"""
        FacebookAdsApi.init(
            app_id=self.config["FB_APP_ID"],
            app_secret=self.config["FB_APP_SECRET"],
            access_token=self.config["USER_TOKEN"],
        )

    def initAccount(self) -> AdAccount:
        """Initialize and return the AdAccount instance"""
        return AdAccount(f"act_{self.config['AD_ACCOUNT_ID']}")

    def getPageAccessToken(self) -> str:
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

    def uploadImage(self, image_path: str | None = None) -> dict[str, str]:
        """Upload image to Facebook and return hash, url, and id"""
        if not image_path:
            image_path = "test-ad-img.jpeg"

        with open(image_path, "rb") as image_file:
            image_bytes = image_file.read()

        params = {
            "filename": image_path.split("/")[-1],
            "bytes": b64encode(image_bytes).decode("utf-8"),
        }
        image = self.account.create_ad_image(params=params)
        return {"hash": image["hash"], "url": image["url"], "id": image["id"]}

    def createMessageCampaign(self) -> Any:
        """Create campaign optimised for message engagement"""
        params = {
            "name": f"Message Engagement Campaign {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "objective": "OUTCOME_AWARENESS",
            "status": "PAUSED",
            "special_ad_categories": [],
            "daily_budget": 2000,  # $20 daily budget
        }
        return self.account.create_campaign(params=params)

    def createMessageAd(self) -> Optional[dict[str, str]]:
        """Create complete message engagement ad"""
        try:
            campaign = self.createMessageCampaign()
            campaign_id = campaign.get_id()
            adset = self.createMessageAdSet(campaign_id)
            creative = self.createMessageCreative()
            ad = self.createAd(adset.get_id(), creative.get_id())
            return {
                "campaign_id": campaign.get_id(),
                "adset_id": adset.get_id(),
                "ad_id": ad.get_id(),
                "creative_id": creative.get_id(),
            }
        except Exception as e:
            print(f"Error creating message ad: {str(e)}")
            return None

    def createMessageCreative(self) -> Any:
        """Create message engagement creative"""
        img = self.uploadImage()

        MESSAGE_VARIANTS = [
            "Message us for quick answers!",
            "Chat with our team now",
            "Need help? Send us a message",
            "We're here to help - message us",
            "Get instant support via Messenger",
        ]
        HEADLINE_VARIANTS = [
            "Chat With Us",
            "Message Our Team",
            "Get Answers Now",
            "Personalized Support",
            "Instant Assistance",
        ]
        DESCRIPTION_VARIANTS = [
            "We respond within minutes to all customer inquiries",
            "Our expert team is standing by to help you",
            "Fast and friendly service through Messenger",
            "No waiting on hold - just message us directly",
            "Connect with our specialists for immediate help",
        ]
        creative_params = {
            "name": f"Message Ad {datetime.now().date()}",
            "object_story_spec": {
                "page_id": self.config["PAGE_ID"],
                "link_data": {
                    "image_hash": img["hash"],
                    "name": HEADLINE_VARIANTS[0],
                    "message": MESSAGE_VARIANTS[0],
                    "call_to_action": {
                        "type": "MESSAGE_PAGE",
                        "value": {"link": f"https://m.me/{self.config['PAGE_ID']}"},
                    },
                    "link": f"https://m.me/{self.config['PAGE_ID']}",
                    "description": DESCRIPTION_VARIANTS[0],
                },
            },
        }
        try:
            print("Validating creative...")
            self.account.create_ad_creative(
                params={**creative_params, "validate_only": True}
            )
            print("Creating creative...")
            return self.account.create_ad_creative(params=creative_params)
        except FacebookRequestError as e:
            print(f"Creative creation failed: {e.api_error_message()}")
            raise

    def createMessageAdSet(self, campaign_id: str) -> Any:
        """Create message engagement ad set"""
        targeting = {
            "geo_locations": {"countries": ["US", "GB"]},
            "age_min": 25,
            "age_max": 65,
            "publisher_platforms": ["facebook"],
            "facebook_positions": ["feed", "marketplace"],
            "locales": [6, 24],  # English (US/UK)
        }

        params = {
            "name": f"Message AdSet {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "campaign_id": campaign_id,
            "status": "PAUSED",
            "billing_event": AdSet.OptimizationGoal.impressions,
            "optimization_goal": AdSet.OptimizationGoal.impressions,
            "bid_amount": "1000",  # $10 bid cap
            "targeting": targeting,
            "promoted_object": {"page_id": self.config["PAGE_ID"]},
            "is_dynamic_creative": False,
            "start_time": (datetime.now() + timedelta(days=1)).strftime(
                "%Y-%m-%dT%H:%M:%S"
            ),
            "end_time": (datetime.now() + timedelta(days=30)).strftime(
                "%Y-%m-%dT%H:%M:%S"
            ),
        }
        return self.account.create_ad_set(params=params)

    def createLeadCampaign(self) -> Any:
        """Create campaign optimized for lead generation"""
        return self.account.create_campaign(
            params={
                "name": f"Lead Generation Campaign {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                "objective": "OUTCOME_LEADS",
                "status": "PAUSED",
                "special_ad_categories": [],
                "daily_budget": 2000,  # $20 daily budget
                "campaign_budget_optimization_toggling_behavior": "ENABLED",
            }
        )

    def createLeadAdSet(self, campaign_id: str) -> Any:
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
            "name": f"Lead Gen AdSet {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "campaign_id": campaign_id,
            "status": "PAUSED",
            "billing_event": "IMPRESSIONS",
            "optimization_goal": AdSet.OptimizationGoal.lead_generation,
            "bid_amount": "1000",  # $10 bid cap
            "targeting": targeting,
            "promoted_object": {"page_id": self.config["PAGE_ID"]},
            "is_dynamic_creative": False,
            "start_time": (datetime.now() + timedelta(days=1)).strftime(
                "%Y-%m-%dT%H:%M:%S"
            ),
            "end_time": (datetime.now() + timedelta(days=30)).strftime(
                "%Y-%m-%dT%H:%M:%S"
            ),
        }
        return self.account.create_ad_set(params=params)

    def createLeadCreative(self) -> Any:
        """Create lead ad creative with multiple variations"""
        img = self.uploadImage()

        MESSAGE_VARIANTS = [
            "Get exclusive offers - sign up today!",
            "Limited time offer - claim your discount now",
            "We're hiring! Apply through this form",
            "Free consultation - get started today",
            "Download our premium guide instantly",
        ]
        HEADLINE_VARIANTS = [
            "Chat With Us",
            "Message Our Team",
            "Get Answers Now",
            "Personalized Support",
            "Instant Assistance",
        ]
        DESCRIPTION_VARIANTS = [
            "We respond within minutes to all customer inquiries",
            "Our expert team is standing by to help you",
            "Fast and friendly service through Messenger",
            "No waiting on hold - just message us directly",
            "Connect with our specialists for immediate help",
        ]
        LANDING_PAGE_URL = "https://concretedesignpro.com/"

        creative_params = {
            "name": f"Lead Ad Variants {datetime.now().date()}",
            "object_story_spec": {
                "page_id": self.config["PAGE_ID"],
                "link_data": {
                    "image_hash": img["hash"],
                    "name": HEADLINE_VARIANTS[0],
                    "message": MESSAGE_VARIANTS[0],
                    "call_to_action": {
                        "type": "SIGN_UP",
                        "value": {"link": LANDING_PAGE_URL},
                    },
                    "description": DESCRIPTION_VARIANTS[0],
                    "link": LANDING_PAGE_URL,
                },
            },
        }

        try:
            print("Validating creative...")
            self.account.create_ad_creative(
                params={**creative_params, "validate_only": True}
            )
            print("Creating creative...")
            return self.account.create_ad_creative(params=creative_params)
        except FacebookRequestError as e:
            print(f"Creative creation failed: {e.api_error_message()}")
            raise

    def createAd(self, adset_id: str, creative_id: str) -> Any:
        """Create the final ad"""
        adset = AdSet(adset_id).api_get(fields=["status", "is_dynamic_creative"])
        if adset["status"] != "PAUSED":
            raise ValueError("AdSet is not in PAUSED status")
        if adset["is_dynamic_creative"]:
            raise ValueError("AdSet is dynamic creative, not supported")

        params = {
            "name": f"Ad {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "adset_id": adset_id,
            "status": "PAUSED",
            "creative": {"creative_id": creative_id},
            "access_token": self.config["USER_TOKEN"],
        }

        print("Creating ad...")
        result = self.account.create_ad(params=params)
        print("Ad created successfully:", result.get_id())
        return result

    def getLeads(self, days_back: int = 7) -> list[dict[str, Any]]:
        """Retrieve leads from lead gen forms with proper parameter handling"""
        try:
            page_access_token = self.getPageAccessToken()
            if not page_access_token:
                raise ValueError("Could not get page access token")

            FacebookAdsApi.init(
                self.config["FB_APP_ID"],
                self.config["FB_APP_SECRET"],
                page_access_token,
            )

            since_date = (datetime.now() - timedelta(days=days_back)).strftime(
                "%Y-%m-%d"
            )
            page = Page(self.config["PAGE_ID"])

            forms_with_names = [
                {"id": form["id"], "name": form.get("name", "Unnamed")}
                for form in page.get_lead_gen_forms(fields=["id", "name"])
            ]

            if not forms_with_names:
                print("No lead generation forms found for the page.")
                return []

            print("Available lead gen forms:")
            for form in forms_with_names:
                print(f"Form ID: {form['id']}, Name: {form['name']}")

            leads_data = []
            for form in forms_with_names:
                try:
                    params = {
                        "fields": "id,created_time,field_data,is_test_lead",
                        "filtering": [
                            {
                                "field": "time_created",
                                "operator": "GREATER_THAN",
                                "value": since_date,
                            }
                        ],
                    }
                    leads = LeadgenForm(form["id"]).get_leads(params=params)
                    print(f"Found {len(leads)} leads for form {form['id']}")

                    for lead in leads:
                        leads_data.append(
                            {
                                "id": lead["id"],
                                "created_time": lead["created_time"],
                                "form_name": form["name"],
                                "is_test_lead": lead.get("is_test_lead", False),
                                "data": {
                                    f["name"]: f["values"][0]
                                    for f in lead.get("field_data", [])
                                },
                            }
                        )
                except FacebookRequestError as e:
                    print(
                        f"Error retrieving leads for form {form['id']}: {e.api_error_message()}"
                    )
                    continue
            return leads_data
        except FacebookRequestError as e:
            print(f"Facebook API Error retrieving leads: {e.api_error_message()}")
            return []
        except Exception as e:
            print(f"Error retrieving leads: {str(e)}")
            return []

    def createLeadAd(self) -> Optional[dict[str, str]]:
        """Create complete lead generation ad"""
        try:
            campaign = self.createLeadCampaign()
            campaign_id = campaign.get_id()
            adset = self.createLeadAdSet(campaign_id)
            creative = self.createLeadCreative()
            ad = self.createAd(adset.get_id(), creative.get_id())
            return {
                "campaign_id": campaign.get_id(),
                "adset_id": adset.get_id(),
                "ad_id": ad.get_id(),
                "creative_id": creative.get_id(),
            }
        except Exception as e:
            print(f"Error creating lead ad: {str(e)}")
            return None


def runAdCreation(manager: FacebookAdsManager, ad_type: AdTypeEnum) -> None:
    """Execute ad creation based on type"""
    if ad_type.value == "lead":
        print("\n1. Creating Lead Generation Ad...")
        ad_result = manager.createLeadAd()
    elif ad_type.value == "message":
        print("\n1. Creating Message Engagement Ad...")
        ad_result = manager.createMessageAd()
    else:
        print("Invalid ad type specified")
        return

    if not ad_result:
        print("Ad creation failed.")
        return

    print("\n2. Ad Creation Successful!")
    print("Campaign ID:", ad_result["campaign_id"])
    print("Ad Set ID:", ad_result["adset_id"])
    print("Ad ID:", ad_result["ad_id"])
    print("Creative ID:", ad_result["creative_id"])


def runLeadRetrieval(manager: FacebookAdsManager, days_back: int = 7) -> None:
    """Execute lead retrieval and display results"""
    print("\n3. Retrieving Facebook Leads...")
    leads = manager.getLeads(days_back)
    print(f"Found {len(leads)} leads:")
    for lead in leads:
        print(f"\nLead ID: {lead['id']}")
        print(f"Date: {lead['created_time']}")
        for field, value in lead["data"].items():
            print(f"{field}: {value}")


def main() -> None:
    """Main execution flow"""
    try:
        manager = FacebookAdsManager()
        # run lead generation ad
        runAdCreation(manager, ad_type=AdTypeEnum.LEAD)
        # run message engagement ad
        runAdCreation(manager, ad_type=AdTypeEnum.MESSAGE)
        runLeadRetrieval(manager, days_back=7)
    except ValueError as e:
        print(f"Configuration error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
