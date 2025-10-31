from django import forms
from django.db.models import Q

from devices.models import Device

from .models import GasMonitorDevice


class GasMonitorDeviceForm(forms.ModelForm):
    class Meta:
        model = GasMonitorDevice
        fields = [
            "device",
            "location",
            "installation_date",
            "last_maintenance_date",
            "status",
        ]
        widgets = {
            "device": forms.Select(attrs={"class": "form-select"}),
            "location": forms.TextInput(
                attrs={"class": "form-control", "placeholder": "e.g. Boiler Room"}
            ),
            "installation_date": forms.DateInput(
                attrs={"class": "form-control", "type": "date"}
            ),
            "last_maintenance_date": forms.DateInput(
                attrs={"class": "form-control", "type": "date"}
            ),
            "status": forms.Select(attrs={"class": "form-select"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        qs = Device.objects.filter(device_type="gas_monitor").filter(
            Q(gas_monitor__isnull=True) | Q(gas_monitor=self.instance)
        )
        self.fields["device"].queryset = qs.order_by("located_at")
        self.fields["device"].help_text = "Choose the base device for this monitor."
        self.fields["location"].widget.attrs.setdefault("autocomplete", "off")

    def clean_device(self):
        device = self.cleaned_data["device"]

        if device.device_type != "gas_monitor":
            raise forms.ValidationError("Select a device configured as a gas monitor.")

        conflict_qs = GasMonitorDevice.objects.filter(device=device)
        if self.instance.pk:
            conflict_qs = conflict_qs.exclude(pk=self.instance.pk)
        if conflict_qs.exists():
            raise forms.ValidationError(
                "This device already has gas monitor details registered."
            )

        return device

    def clean(self):
        cleaned_data = super().clean()
        installation_date = cleaned_data.get("installation_date")
        maintenance_date = cleaned_data.get("last_maintenance_date")

        if (
            installation_date
            and maintenance_date
            and maintenance_date < installation_date
        ):
            self.add_error(
                "last_maintenance_date",
                "Maintenance date cannot be earlier than installation date.",
            )

        return cleaned_data
