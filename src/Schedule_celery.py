from celery import Celery
from dotenv import load_dotenv
import os

env_path= "src/Variables.env"
load_dotenv(env_path)

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL")

celery_app = Celery('tasks', broker=CELERY_BROKER_URL)
@celery_app.task
def process_file_task(document_id, priority):
    # Placeholder implementation
    if priority:
        print(f"Processing file with document ID {document_id} immediately.")
        # Your processing logic here
    else:
        print(f"Scheduling file with document ID {document_id} for off-peak hours.")
        # Scheduling logic here
