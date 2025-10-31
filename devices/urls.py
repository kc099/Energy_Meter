from django.urls import path
from . import views

app_name = 'devices'

urlpatterns = [
    path('', views.device_list, name='device_list'),
    path('add/', views.add_device, name='add_device'),
    path('download/', views.download_devices_csv, name='download_devices'),
    path('config/<int:device_id>/', views.device_config_detail, name='device_config_detail'),
    path('token/<int:device_id>/', views.device_token_detail, name='device_token_detail'),
    path('token/<int:device_id>/otp/', views.device_token_request_otp, name='device_token_request_otp'),
    path('share/', views.bulk_share_devices, name='bulk_share_devices'),
    path('<int:device_id>/', views.device_detail, name='device_detail'),
    path('<int:device_id>/remove/', views.remove_device, name='remove_device'),
    path('<int:device_id>/provision/', views.device_provisioning, name='device_provisioning'),
    path('<int:device_id>/report/', views.device_report, name='device_report'),
    path('shifts/reports/', views.shift_reports, name='shift_reports'),
    path('shifts/', views.manage_shifts, name='manage_shifts'),
    path('shifts/add/', views.add_shift, name='add_shift'),
    path('shifts/<int:shift_id>/edit/', views.edit_shift, name='edit_shift'),
    path('shifts/<int:shift_id>/toggle/', views.toggle_shift, name='toggle_shift'),
    path('<int:device_id>/share/', views.share_device, name='share_device'),
    path('<int:device_id>/remove_shared_user/<int:user_id>/', views.remove_shared_user, name='remove_shared_user'),
]
