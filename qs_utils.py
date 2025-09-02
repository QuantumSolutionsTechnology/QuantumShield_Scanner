from datetime import datetime

# Utility function to get the current timestamp in "YYYYMMDD_HHMM" format
def get_current_timestamp():
    now = datetime.now()

    return now.strftime("%Y%m%d_%H%M")