from datetime import datetime, timedelta
import time
import pytz

def localTime(zone = 'Asia/Kolkata'):
    IST = pytz.timezone(zone)
    return datetime.now(IST)

