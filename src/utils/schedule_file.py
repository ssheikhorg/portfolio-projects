from celery import Celery
from dotenv import load_dotenv
import os
from src.utils.Logging import logs

env_path= "src/Variables.env"
load_dotenv(env_path)

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL")

celery_app = Celery('tasks', broker=CELERY_BROKER_URL)

@celery_app.task
def process_file_task(document_id, priority):
    """
    Process a file task.
    If priority is True, process the file immediately.
    Otherwise, schedule the file for off-peak hours.
    """
    try:
        if priority:
            # Your processing logic here
            logs('info', f"Processing file with document ID {document_id} immediately.")
        else:
            # Scheduling logic here
            logs('info', f"Scheduling file with document ID {document_id} for off-peak hours.")
    except Exception as e:
        logs('critical', "An error occurred in process_file_task", str(e))
