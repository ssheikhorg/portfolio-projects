import os
import shutil
import tempfile
from datetime import datetime, timedelta


def cleanup_temp_files():
    # Get the system's temp directory
    temp_dir = tempfile.gettempdir()

    # Calculate the cutoff time (e.g., 24 hours ago)
    cutoff_time = datetime.now() - timedelta(hours=24)

    for root, dirs, files in os.walk(temp_dir):
        for name in files + dirs:
            path = os.path.join(root, name)

            # Check if the file/directory is older than the cutoff time
            if os.path.getctime(path) < cutoff_time.timestamp():
                try:
                    if os.path.isfile(path):
                        os.remove(path)
                    elif os.path.isdir(path):
                        shutil.rmtree(path)
                    print(f"Removed: {path}")
                except Exception as e:
                    print(f"Error removing {path}: {str(e)}")


if __name__ == "__main__":
    cleanup_temp_files()
