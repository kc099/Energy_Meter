from django import forms
from .models import GasMonitorDevice

class GasMonitorDeviceForm(forms.ModelForm):
    device_name = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'id': 'device_name'
        })
    )
    gas_type = forms.ChoiceField(
        choices=GasMonitorDevice.GAS_TYPE_CHOICES,
        widget=forms.Select(attrs={
            'class': 'form-control',
            'id': 'gas_type'
        })
    )
    threshold_value = forms.FloatField(
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'id': 'threshold_value'
        })
    )

    class Meta:
        model = GasMonitorDevice
        fields = ['device_name', 'location', 'gas_type', 'threshold_value']


    def clean_threshold_value(self):
        value = self.cleaned_data.get('threshold_value')
        if value is not None and value < 0:
            raise forms.ValidationError("Threshold value must be non-negative")
        return value
    def clean_device_name(self):
        name = self.cleaned_data.get('device_name')
        if GasMonitorDevice.objects.filter(name=name).exists():
            raise forms.ValidationError("A device with this name already exists.")
        return name
    def clean_location(self):
        location = self.cleaned_data.get('location')
        if not location:
            raise forms.ValidationError("Location cannot be empty.")
        return location
    def clean_gas_type(self):
        gas_type = self.cleaned_data.get('gas_type')
        if gas_type not in dict(GasMonitorDevice.GAS_TYPE_CHOICES).keys():
            raise forms.ValidationError("Invalid gas type selected.")
        return gas_type

