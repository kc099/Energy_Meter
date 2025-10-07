# from django.core.management.base import BaseCommand
# from django.utils import timezone
# from django.db.models import Avg, Min, Max
# from devices.models import Device, DeviceData, Shift, ShiftReport
# from datetime import datetime, time, timedelta
# import time as time_lib
# import logging

# logger = logging.getLogger(__name__)

# class Command(BaseCommand):
#     help = 'Polls all active devices for data'

#     def generate_shift_report(self, device, shift, date):
#         """Generate shift report for a device"""
#         start_datetime = timezone.make_aware(datetime.combine(date, shift.start_time))
#         end_datetime = timezone.make_aware(datetime.combine(date, shift.end_time))
        
#         # If shift ends next day
#         if shift.start_time > shift.end_time:
#             end_datetime += timedelta(days=1)
        
#         # Get data for the shift period
#         shift_data = DeviceData.objects.filter(
#             device=device,
#             timestamp__range=(start_datetime, end_datetime)
#         )
        
#         if shift_data.exists():
#             # Calculate metrics
#             metrics = shift_data.aggregate(
#                 min_pf=Min('value__power_factor'),
#                 max_pf=Max('value__power_factor'),
#                 avg_pf=Avg('value__power_factor')
#             )
            
#             # Get timestamps for min/max power factor
#             min_pf_record = shift_data.filter(value__power_factor=metrics['min_pf']).first()
#             max_pf_record = shift_data.filter(value__power_factor=metrics['max_pf']).first()
            
#             # Calculate total kWh
#             first_reading = shift_data.first()
#             last_reading = shift_data.last()
#             total_kwh = last_reading.value.get('kwh', 0) - first_reading.value.get('kwh', 0)
            
#             # Create or update shift report
#             ShiftReport.objects.update_or_create(
#                 shift=shift,
#                 device=device,
#                 date=date,
#                 defaults={
#                     'min_power_factor': metrics['min_pf'],
#                     'max_power_factor': metrics['max_pf'],
#                     'min_power_factor_time': min_pf_record.timestamp if min_pf_record else start_datetime,
#                     'max_power_factor_time': max_pf_record.timestamp if max_pf_record else start_datetime,
#                     'avg_power_factor': metrics['avg_pf'],
#                     'total_kwh': total_kwh if total_kwh > 0 else 0
#                 }
#             )

#     def check_and_generate_reports(self, device, shifts, current_time):
#         """Check if any shifts have completed and generate reports"""
#         current_date = current_time.date()
#         current_time_only = current_time.time()

#         for shift in shifts:
#             # Check if we need to generate a report for this shift
#             report_exists = ShiftReport.objects.filter(
#                 shift=shift,
#                 device=device,
#                 date=current_date
#             ).exists()

#             # Only generate if report doesn't exist and shift has ended
#             if not report_exists:
#                 # Check if shift has completed
#                 shift_completed = False

#                 if shift.start_time > shift.end_time:
#                     # Shift crosses midnight
#                     if current_time_only < shift.start_time and current_time_only >= shift.end_time:
#                         shift_completed = True
#                 else:
#                     # Regular shift within same day
#                     if current_time_only >= shift.end_time:
#                         shift_completed = True

#                 if shift_completed:
#                     self.stdout.write(f'Generating report for {shift.name} on {current_date}')
#                     self.generate_shift_report(device, shift, current_date)

#     def handle(self, *args, **options):
#         self.stdout.write('Starting device polling service...')
        
#         while True:
#             try:
#                 current_time = timezone.now()
#                 devices = Device.objects.filter(is_active=True)
#                 active_shifts = Shift.objects.filter(is_active=True)
                
#                 for device in devices:
#                     try:
#                         success, data = device.poll_device()
                        
#                         if success:
#                             self.stdout.write(
#                                 self.style.SUCCESS(f'Successfully polled device {device} at {current_time}')
#                             )
                            
#                             # Generate shift reports for completed shifts
#                             self.check_and_generate_reports(device, active_shifts, current_time)
#                         else:
#                             self.stdout.write(
#                                 self.style.ERROR(f'Failed to poll device {device} at {current_time}: {data}')
#                             )
#                     except Exception as e:
#                         self.stdout.write(
#                             self.style.ERROR(f'Error polling device {device}: {str(e)}')
#                         )

#                 # Wait for polling interval (5 seconds)
#                 time_lib.sleep(5)
#             except Exception as e:
#                 logger.error(f"Error in device polling: {str(e)}")
#                 time_lib.sleep(5)  # Wait 5 seconds before retrying on error




# devices/management/commands/poll_devices.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db.models import Avg, Min, Max
from devices.models import Device, DeviceData, Shift, ShiftReport
from datetime import datetime, time, timedelta
import time as time_lib
import logging
import signal
import sys

CHECK_MARK = "\u2713"
CROSS_MARK = "\u2717"

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Polls all active devices for data continuously'
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.shutdown = False
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def add_arguments(self, parser):
        parser.add_argument(
            '--poll-interval',
            type=int,
            default=5,
            help='Polling interval in seconds (default: 5)',
        )

    def exit_gracefully(self, signum, frame):
        self.stdout.write(self.style.WARNING('Shutting down polling service...'))
        self.shutdown = True

    def generate_shift_report(self, device, shift, date):
        """Generate shift report for a device"""
        try:
            start_datetime = timezone.make_aware(datetime.combine(date, shift.start_time))
            end_datetime = timezone.make_aware(datetime.combine(date, shift.end_time))
            
            # If shift ends next day, adjust end datetime
            if shift.end_time <= shift.start_time:
                end_datetime += timedelta(days=1)
            
            # Get data for the shift period
            shift_data = DeviceData.objects.filter(
                device=device,
                timestamp__range=(start_datetime, end_datetime)
            ).order_by('timestamp')
            
            if not shift_data.exists():
                self.stdout.write(f'No data found for {device} during {shift.name} shift on {date}')
                return
            
            # Calculate metrics
            metrics = shift_data.aggregate(
                min_pf=Min('data__power_factor'),
                max_pf=Max('data__power_factor'),
                avg_pf=Avg('data__power_factor'),
                min_voltage=Min('data__voltage'),
                max_voltage=Max('data__voltage'),
                avg_voltage=Avg('data__voltage')
            )
            
            # Get timestamps for min/max power factor
            min_pf_record = shift_data.filter(data__power_factor=metrics['min_pf']).first()
            max_pf_record = shift_data.filter(data__power_factor=metrics['max_pf']).first()
            
            # Calculate total kWh (assuming cumulative reading)
            first_reading = shift_data.first()
            last_reading = shift_data.last()
            
            total_kwh = 0
            if first_reading and last_reading:
                start_kwh = first_reading.data.get('kwh', 0) or 0
                end_kwh = last_reading.data.get('kwh', 0) or 0
                total_kwh = max(0, end_kwh - start_kwh)
            
            # Create or update shift report
            report, created = ShiftReport.objects.update_or_create(
                shift=shift,
                device=device,
                date=date,
                defaults={
                    'min_power_factor': metrics['min_pf'] or 0,
                    'max_power_factor': metrics['max_pf'] or 0,
                    'min_power_factor_time': min_pf_record.timestamp if min_pf_record else start_datetime,
                    'max_power_factor_time': max_pf_record.timestamp if max_pf_record else start_datetime,
                    'avg_power_factor': metrics['avg_pf'] or 0,
                    'min_voltage': metrics['min_voltage'] or 0,
                    'max_voltage': metrics['max_voltage'] or 0,
                    'avg_voltage': metrics['avg_voltage'] or 0,
                    'total_kwh': total_kwh,
                    'data_points': shift_data.count()
                }
            )
            
            if created:
                self.stdout.write(f'Created shift report for {device} - {shift.name} on {date}')
            else:
                self.stdout.write(f'Updated shift report for {device} - {shift.name} on {date}')
                
        except Exception as e:
            logger.error(f"Error generating shift report for {device} - {shift.name}: {str(e)}")
            self.stdout.write(self.style.ERROR(f'Error generating report: {str(e)}'))

    def should_generate_report(self, shift, current_time):
        """Check if it's time to generate report for a shift"""
        current_time_only = current_time.time()
        shift_end = shift.end_time
        
        # Consider buffer time (15 minutes after shift end) to ensure all data is collected
        buffer_time = 15  # minutes
        shift_end_with_buffer = (datetime.combine(datetime.today(), shift_end) + 
                               timedelta(minutes=buffer_time)).time()
        
        if shift.start_time > shift.end_time:
            # Night shift (crosses midnight)
            return (current_time_only >= shift_end and 
                   current_time_only <= shift_end_with_buffer)
        else:
            # Day shift
            return (current_time_only >= shift_end and 
                   current_time_only <= shift_end_with_buffer)

    def check_and_generate_reports(self, device, shifts, current_time):
        """Check if any shifts have completed and generate reports"""
        current_date = current_time.date()
        
        for shift in shifts:
            try:
                # Check if report already exists
                report_exists = ShiftReport.objects.filter(
                    shift=shift,
                    device=device,
                    date=current_date
                ).exists()
                
                # Generate report if it's time and report doesn't exist
                if not report_exists and self.should_generate_report(shift, current_time):
                    self.stdout.write(f'Generating report for {shift.name} on {current_date}')
                    self.generate_shift_report(device, shift, current_date)
                    
            except Exception as e:
                logger.error(f"Error checking reports for {device} - {shift.name}: {str(e)}")
                self.stdout.write(self.style.ERROR(f'Error checking reports: {str(e)}'))

    def handle(self, *args, **options):
        poll_interval = options['poll_interval']
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Starting device polling service with {poll_interval} second interval...'
            )
        )
        self.stdout.write('Press Ctrl+C to stop the service')
        
        consecutive_errors = 0
        max_consecutive_errors = 5
        
        while not self.shutdown:
            try:
                current_time = timezone.now()
                devices = Device.objects.filter(is_active=True)
                active_shifts = Shift.objects.filter(is_active=True)
                
                if not devices.exists():
                    self.stdout.write(self.style.WARNING('No active devices found'))
                    time_lib.sleep(poll_interval)
                    continue
                
                successful_polls = 0
                total_devices = devices.count()
                
                for device in devices:
                    if self.shutdown:
                        break
                        
                    try:
                        success, data = device.poll_device()
                        
                        if success:
                            successful_polls += 1
                            success_message = f'{CHECK_MARK} Polled device {device} successfully'
                            self.stdout.write(self.style.SUCCESS(success_message))
                            if successful_polls % 10 == 0:  # Log every 10th success to reduce noise
                                self.stdout.write(
                                    self.style.SUCCESS(
                                        f'{CHECK_MARK} Polled {successful_polls}/{total_devices} devices'
                                    )
                                )
                            
                            # Generate shift reports for completed shifts
                            self.check_and_generate_reports(device, active_shifts, current_time)
                            
                        else:
                            failure_message = f'{CROSS_MARK} Failed to poll device {device}: {data}'
                            self.stdout.write(self.style.ERROR(failure_message))
                            
                    except Exception as e:
                        logger.error(f"Error polling device {device}: {str(e)}")
                        error_message = f'{CROSS_MARK} Error polling device {device}: {str(e)}'
                        self.stdout.write(self.style.ERROR(error_message))
                
                consecutive_errors = 0  # Reset error counter on successful iteration
                
                # Sleep for polling interval, but check for shutdown frequently
                for _ in range(poll_interval * 2):  # Check every 0.5 seconds
                    if self.shutdown:
                        break
                    time_lib.sleep(0.5)
                    
            except Exception as e:
                consecutive_errors += 1
                logger.error(f"Error in device polling loop: {str(e)}")
                loop_error_message = f'{CROSS_MARK} Error in polling loop: {str(e)}'
                self.stdout.write(self.style.ERROR(loop_error_message))
                
                if consecutive_errors >= max_consecutive_errors:
                    shutdown_message = f'{CROSS_MARK} Too many consecutive errors. Shutting down.'
                    self.stdout.write(self.style.ERROR(shutdown_message))
                    break
                    
                time_lib.sleep(min(30, poll_interval * consecutive_errors))  # Exponential backoff
        
        self.stdout.write(self.style.SUCCESS('Device polling service stopped gracefully'))
