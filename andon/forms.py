from django import forms

from .models import Station


class StationForm(forms.ModelForm):
    """Collects/validates Station fields before saving."""

    class Meta:
        model = Station
        fields = [
            "name",
            "ip_address",
            "topic",
            "plan_shift1",
            "plan_shift2",
            "plan_shift3",
            "is_active",
            "is_alive",
        ]

    def clean_name(self):
        # Keep user input but strip accidental whitespace so comparisons stay consistent.
        return self.cleaned_data["name"].strip()
