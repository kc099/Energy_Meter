from django.db import models
from django.utils import timezone

class ShiftConfig(models.Model):
    shift1_start = models.TimeField()
    shift1_end   = models.TimeField()
    shift2_start = models.TimeField()
    shift2_end   = models.TimeField()
    shift3_start = models.TimeField()
    shift3_end   = models.TimeField()
    # display format: 'alphabetic' (A/B/C) or 'numeric' (1/2/3)
    display_format = models.CharField(max_length=12, default="alphabetic")

class Station(models.Model):
    name = models.CharField(max_length=100, unique=True)
    ip_address = models.CharField(max_length=200)          # same as Tkinter
    topic = models.CharField(max_length=120, blank=True)   # mqtt/topic if any
    plan_shift1 = models.IntegerField(default=0)
    plan_shift2 = models.IntegerField(default=0)
    plan_shift3 = models.IntegerField(default=0)
    actual_count = models.IntegerField(default=0)
    total_downtime_min = models.FloatField(default=0)
    is_active = models.BooleanField(default=True)
    is_alive  = models.BooleanField(default=True)
    last_ping = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def current_plan(self, shift_number: int) -> int:
        return {1: self.plan_shift1, 2: self.plan_shift2, 3: self.plan_shift3}.get(shift_number, 0)

class SectionData(models.Model):
    station = models.ForeignKey(Station, on_delete=models.CASCADE)
    date = models.DateField(default=timezone.localdate)
    fault_time = models.DateTimeField(null=True, blank=True)
    resolved_time = models.DateTimeField(null=True, blank=True)
    calltype = models.CharField(max_length=20, blank=True)  # PMD/Quality/Store/JMD/Production
    topic = models.CharField(max_length=120, blank=True)

class DailyRecord(models.Model):
    station = models.ForeignKey(Station, on_delete=models.CASCADE)
    date = models.DateField()
    plan = models.IntegerField(default=0)
    actual_count = models.IntegerField(default=0)
    efficiency = models.FloatField(default=0.0)

class ShiftData(models.Model):
    station = models.ForeignKey(Station, on_delete=models.CASCADE)
    date = models.DateField()
    shift = models.CharField(max_length=1)  # 'A','B','C' or '1','2','3'
    plan = models.IntegerField(default=0)
    actual = models.IntegerField(default=0)
    downtime_min = models.FloatField(default=0)
    efficiency = models.FloatField(default=0.0)