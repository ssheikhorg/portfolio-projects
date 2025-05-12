import sys

from fb_manager import FacebookAdsManager


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
