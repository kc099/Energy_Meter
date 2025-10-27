import json

from django.contrib import messages
from django.core.serializers.json import DjangoJSONEncoder
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .forms import StationForm
from .models import ShiftConfig, ShiftData, Station


def station_add(request):
    """Create a new Andon station."""

    form = StationForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Station created.")
        return redirect("andon:station_list")

    return render(request, "andon/station_form.html", {"form": form})


def station_list(request):
    stations = Station.objects.order_by("name")
    return render(request, "andon/station_list.html", {"stations": stations})


def station_detail(request, pk):
    station = get_object_or_404(Station, pk=pk)
    recent_shift = (
        ShiftData.objects.filter(station=station).order_by("-date", "-id").first()
    )
    return render(
        request,
        "andon/station_detail.html",
        {
            "station": station,
            "recent_shift": recent_shift,
        },
    )


def station_edit(request, pk):
    """Update an existing station."""

    station = get_object_or_404(Station, pk=pk)
    form = StationForm(request.POST or None, instance=station)

    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Station updated.")
        return redirect("andon:station_detail", pk=station.pk)

    return render(
        request,
        "andon/station_form.html",
        {
            "form": form,
            "station": station,
        },
    )
def station_delete(request, pk):
    station = get_object_or_404(Station, pk=pk)

    if request.method == "POST":
        station.delete()
        messages.success(request, "Station deleted.")
        return redirect("andon:station_list")

    return render(request, "andon/station_confirm_delete.html", {"station": station})       

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
        "right_logo_url": "/static/OGIHARA1.PNG",
        # Serialize once so the template can feed the JS carousel without manual string building.
        "stations_json": json.dumps(station_cards, cls=DjangoJSONEncoder),
    }
    return render(request, "andon/dashboard.html", context)
