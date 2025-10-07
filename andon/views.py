from django.shortcuts import render
from django.utils import timezone
from .models import Station, ShiftData, ShiftConfig

def dashboard(request):
    cfg = ShiftConfig.objects.first()
    today = timezone.localdate()

    # Prepare the same fields your Tk app displays on each card
    station_cards = []
    for s in Station.objects.order_by("name"):
        sd = (
            ShiftData.objects
            .filter(station=s, date=today)
            .order_by("-id")
            .first()
        )

        station_cards.append({
            "id": s.id,
            "name": s.name,
            "plan": (sd.plan if sd else 0),
            # show "shift-relative" actual on UI (as in Tkinter update) 
            "actual": (sd.actual if sd else 0),   # you can store shift-relative here
            "downtime_min": (sd.downtime_min if sd else 0.0),
            "fault_time": "",      # fill from your SectionData if desired
            "resolved_time": "",   # fill from your SectionData if desired
            "ip": s.ip_address,
            "created_at": s.created_at,
            "last_updated": s.last_ping,
            "is_active": (s.is_active and s.is_alive),
        })

    context = {
        "stations": station_cards,   # list of cards to slide through
        "left_logo_url": "/static/JBM.PNG",      # use your real static paths
        "right_logo_url": "/static/OGIHARA1.PNG"
    }
    return render(request, "andon/dashboard.html", context)
