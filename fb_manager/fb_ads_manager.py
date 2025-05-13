import random
import sys
from base64 import b64encode
from datetime import datetime, timedelta
from os import getenv

from dotenv import load_dotenv
from typing import Optional, Any

from facebook_business.adobjects.page import Page
from facebook_business.adobjects.user import User
from facebook_business.api import FacebookAdsApi
from facebook_business.adobjects.adaccount import AdAccount
from facebook_business.exceptions import FacebookRequestError
from facebook_business.adobjects.adset import AdSet
from facebook_business.adobjects.leadgenform import LeadgenForm


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
        self.config = self._load_config()
        self._validate_config()
        self._init_api()

    def _load_config(self) -> dict[str, str]:
        """Load configuration from dict or environment variables"""
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

    def _upload_image_file(
        self, account: AdAccount, image_path: str | None = None
    ) -> dict[str, str]:
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
            "is_dynamic_creative": False,
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
            "Chat With Us",
            "Message Our Team",
            "Get Answers Now",
            "Personalized Support",
            "Instant Assistance",
        ]
        DESCRIPTIONS = [
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
                "page_id": page_id,
                "link_data": {
                    "image_hash": img["hash"],
                    "name": random.choice(HEADLINES),
                    "message": random.choice(MESSAGES),
                    "call_to_action": {
                        "type": "SIGN_UP",
                        "value": {"link": LANDING_PAGE_URL},
                    },
                    "description": random.choice(DESCRIPTIONS),
                    "link": LANDING_PAGE_URL,
                },
            },
        }

        try:
            print("Validating creative...")
            account.create_ad_creative(
                params={**creative_params, "validate_only": True}
            )
            print("Creating creative...")
            return account.create_ad_creative(params=creative_params)
        except FacebookRequestError as e:
            print(f"Creative creation failed: {e.api_error_message()}")
            raise

    def _create_ad(self, account: AdAccount, adset_id: str, creative_id: str) -> Any:
        """Create the final ad"""
        # Verify adset status
        adset = AdSet(adset_id).api_get(fields=["status", "is_dynamic_creative"])
        if adset["status"] != "PAUSED":
            raise ValueError("AdSet is not in PAUSED status")
        if adset["is_dynamic_creative"]:
            raise ValueError("AdSet is dynamic creative, not supported")

        # Prepare ad parameters
        params = {
            "name": f"Lead Ad {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "adset_id": adset_id,
            "status": "PAUSED",
            "creative": {"creative_id": creative_id},
            "access_token": self.config["USER_TOKEN"],
        }

        print("Creating ad...")
        result = account.create_ad(params=params)
        print("Ad created successfully:", result.get_id())
        return result

    def get_ad_account(self) -> AdAccount:
        """Get the AdAccount instance"""
        return AdAccount(f"act_{self.config['AD_ACCOUNT_ID']}")

    def get_leads(self, days_back: int = 7) -> list[dict[str, Any]]:
        """Retrieve leads from lead gen forms with proper parameter handling"""
        try:
            page_access_token = self._get_page_access_token()
            if not page_access_token:
                raise ValueError("Could not get page access token")

            # Reinitialize API with page access token
            FacebookAdsApi.init(
                self.config["FB_APP_ID"],
                self.config["FB_APP_SECRET"],
                page_access_token,
            )

            since_date = (datetime.now() - timedelta(days=days_back)).strftime(
                "%Y-%m-%d"
            )
            page = Page(self.config["PAGE_ID"])

            # First get all forms with their names
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
                    # Prepare params dictionary with filtering
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

                    # Get leads for this form using params
                    leads = LeadgenForm(form["id"]).get_leads(params=params)

                    print(f"Found {len(leads)} leads for form {form['id']}")

                    # Process leads while preserving form name
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

    def create_message_ad(self) -> Optional[dict[str, str]]:
        """Create message engagement ad with multiple text variations"""
        try:
            account = self.get_ad_account()
            page_id = self.config["PAGE_ID"]

            campaign = self._create_campaign(account)
            campaign_id = campaign.get_id()
            adset = self._create_ad_set(account, campaign_id, page_id)
            creative = self._create_ad_creative(account, page_id)
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


def run_ad_creation(manager: FacebookAdsManager):
    """Execute ad creation and display results"""
    print("\n1. Creating Message Engagement Ad...")
    ad_result = manager.create_message_ad()
    if not ad_result:
        print("Ad creation failed.")
        return

    print("\n2. Ad Creation Successful!")
    print("Campaign ID:", ad_result["campaign_id"])
    print("Ad Set ID:", ad_result["adset_id"])
    print("Ad ID:", ad_result["ad_id"])
    print("Creative ID:", ad_result["creative_id"])


def run_lead_retrieval(manager: FacebookAdsManager, days_back: int = 7):
    """Execute lead retrieval and display results"""
    print("\n3. Retrieving Facebook Leads...")
    leads = manager.get_leads(days_back)
    print(f"Found {len(leads)} leads:")
    for lead in leads:
        print(f"\nLead ID: {lead['id']}")
        print(f"Date: {lead['created_time']}")
        for field, value in lead["data"].items():
            print(f"{field}: {value}")


def main():
    """Main execution flow"""
    try:
        manager = FacebookAdsManager()
        run_ad_creation(manager)
        run_lead_retrieval(manager, days_back=7)
    except ValueError as e:
        print(f"Configuration error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        sys.exit(1)
