#this code is used to poll andon stations and update their status in the database
import requests, datetime
from celery import shared_task
from django.utils import timezone
from .models import Station, ShiftConfig, ShiftData, DailyRecord

def get_current_shift(cfg: ShiftConfig, now=None):
    now = now or timezone.localtime()
    def in_range(start, end):
        s = datetime.datetime.combine(now.date(), start).time()
        e = datetime.datetime.combine(now.date(), end).time()
        if s <= e:
            return s <= now.time() <= e
        # overnight wrap
        return now.time() >= s or now.time() <= e
    if in_range(cfg.shift1_start, cfg.shift1_end): return 1
    if in_range(cfg.shift2_start, cfg.shift2_end): return 2
    return 3

@shared_task
def poll_andon_stations():
    cfg = ShiftConfig.objects.first()
    shift = get_current_shift(cfg)
    for st in Station.objects.filter(is_active=True):
        url = st.ip_address if st.ip_address.startswith("http") else f"http://{st.ip_address}"
        try:
            r = requests.get(url.rstrip('/') + "/data", timeout=5)
            r.raise_for_status()
            text = r.text.strip()
            # your Tkinter code parses CSV-ish strings. Keep it simple here:
            # e.g. "plan,actual,downtime" or vendor specific -> adapt as needed
            parts = [p.strip() for p in text.strip("{}").split(",")]
            # fallbacks
            plan = st.current_plan(shift)
            actual = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else st.actual_count
            downtime = float(parts[2]) if len(parts) > 2 else 0.0

            st.actual_count = actual
            st.total_downtime_min = downtime
            st.last_ping = timezone.now()
            st.is_alive = True
            st.save()

            # upsert shift row
            sd, _ = ShiftData.objects.get_or_create(
                station=st, date=timezone.localdate(), shift=str(shift if cfg.display_format=="numeric" else "ABC"[shift-1])
            )
            sd.plan = plan
            sd.actual = actual
            sd.downtime_min = downtime
            sd.save()

            # upsert daily record
            dr, _ = DailyRecord.objects.get_or_create(station=st, date=timezone.localdate())
            dr.plan = (st.plan_shift1 + st.plan_shift2 + st.plan_shift3)
            dr.actual_count = max(dr.actual_count, actual)
            dr.efficiency = round((dr.actual_count / dr.plan) * 100, 2) if dr.plan else 0
            dr.save()

        except Exception:
            st.is_alive = False
            st.save()
