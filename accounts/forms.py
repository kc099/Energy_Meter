from django import forms

from devices.models import Shift

from .models import ReportRecipient, User

class UserForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput())
    conform_password = forms.CharField(widget=forms.PasswordInput())
    class Meta:
        model = User
        fields = ['first_name','last_name','username','email','password']
    
    def clean(self):
        cleaned_data = super(UserForm,self).clean()
        password = cleaned_data.get("password")
        conform_password = cleaned_data.get("conform_password")
        if password != conform_password:
            raise forms.ValidationError("passwords do not match")
            return cleaned_data


class ReportRecipientForm(forms.ModelForm):
    class Meta:
        model = ReportRecipient
        fields = ['email', 'send_daily_reports', 'send_shift_reports', 'shifts']

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        super().__init__(*args, **kwargs)
        self.fields['shifts'].required = False
        self.fields['shifts'].queryset = Shift.objects.filter(is_active=True).order_by('start_time')
        self.fields['shifts'].help_text = 'Select one or more shifts that should receive reports.'

        for name, field in self.fields.items():
            widget = field.widget
            if isinstance(widget, forms.CheckboxInput):
                existing = widget.attrs.get('class', '')
                widget.attrs['class'] = f"{existing} form-check-input".strip()
            elif name == 'shifts':
                existing = widget.attrs.get('class', '')
                widget.attrs['class'] = f"{existing} form-select".strip()
                widget.attrs.setdefault('size', 4)
            else:
                existing = widget.attrs.get('class', '')
                widget.attrs['class'] = f"{existing} form-control".strip()

            if name != 'shifts' and not isinstance(widget, forms.CheckboxInput):
                widget.attrs.setdefault('autocomplete', 'off')

    def clean_email(self):
        email = self.cleaned_data['email'].strip().lower()
        return email

    def clean(self):
        cleaned_data = super().clean()
        send_daily = cleaned_data.get('send_daily_reports')
        send_shift = cleaned_data.get('send_shift_reports')
        shifts = cleaned_data.get('shifts')

        if not send_daily and not send_shift:
            raise forms.ValidationError('Select at least one report type (shift or daily).')

        if send_shift and not shifts:
            self.add_error('shifts', 'Choose at least one shift when shift reports are enabled.')

        return cleaned_data

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.user = self.user
        if commit:
            instance.save()
            self.save_m2m()
        return instance
