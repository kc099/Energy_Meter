from django import forms
from .models import Device

class DeviceForm(forms.ModelForm):
    address_type = forms.ChoiceField(
        choices=Device.ADDRESS_TYPE_CHOICES,
        initial='ip',
        widget=forms.RadioSelect,
        help_text='Select the type of address you want to use'
    )
    
    device_address = forms.CharField(
        max_length=200,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'id': 'device_address'
        })
    )

    class Meta:
        model = Device
        fields = ['device_type', 'located_at', 'address_type', 'device_address']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['device_address'].help_text = '''
            For IP Address: Enter device IP (e.g., 192.168.0.124)
            For API Endpoint: Enter full URL (e.g., http://127.0.0.1:8000/api/device/1/getdata/)
        '''

    def clean_device_address(self):
        addr = self.cleaned_data.get('device_address')
        addr_type = self.cleaned_data.get('address_type')

        if addr_type == 'ip':
            # Validate IP address format
            if ':' in addr:  # Handle IP with port
                ip_part, port = addr.split(':')
                try:
                    port = int(port)
                    if not 1 <= port <= 65535:
                        raise forms.ValidationError("Port number must be between 1 and 65535")
                except ValueError:
                    raise forms.ValidationError("Invalid port number")
            else:
                ip_part = addr

            # Validate IP part
            parts = ip_part.split('.')
            if len(parts) != 4:
                raise forms.ValidationError("Please enter a valid IP address (e.g., 192.168.0.124)")
            for part in parts:
                try:
                    if not 0 <= int(part) <= 255:
                        raise forms.ValidationError("IP address numbers must be between 0 and 255")
                except ValueError:
                    raise forms.ValidationError("IP address must contain only numbers and dots")
        else:  # api type
            # Basic validation for API endpoint
            if not addr.startswith(('http://', 'https://')):
                # If no protocol specified, assume http://
                addr = f"http://{addr}"

        return addr