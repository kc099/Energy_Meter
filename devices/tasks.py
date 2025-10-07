"""Celery tasks for polling device data asynchronously."""
import logging
import csv
from io import StringIO
from datetime import datetime, timedelta

try:
    from celery import shared_task
except ModuleNotFoundError:  # pragma: no cover - allow running without Celery installed
    def shared_task(*dargs, **dkwargs):
        def decorator(func):
            return func

        return decorator

from django.utils import timezone
from django.core.mail import EmailMessage
from django.conf import settings

from .models import Device, Shift, ShiftReport
from accounts.models import User

logger = logging.getLogger(__name__)


def _should_poll(device, reference_time):
    """Return True when the device is due for polling."""
    if device.polling_interval <= 0:
        return False

    if device.last_updated is None:
        return True

    elapsed = (reference_time - device.last_updated).total_seconds()
    return elapsed >= device.polling_interval


def _execute_poll(device):
    """Poll the device and log the outcome."""
    success, payload = device.poll_device()
    if success:
        logger.info("Polled device %s successfully", device.id)
    else:
        logger.warning("Polling device %s failed: %s", device.id, payload)


@shared_task(bind=True, ignore_result=True)
def poll_device_task(self, device_id, force=False):
    """Poll a single device, optionally bypassing recency checks."""
    try:
        device = Device.objects.get(id=device_id)
    except Device.DoesNotExist:
        logger.warning("Device %s no longer exists; skipping poll", device_id)
        return

    now = timezone.now()
    if not force and not _should_poll(device, now):
        logger.debug("Skipping poll for device %s; updated recently", device_id)
        return

    _execute_poll(device)


@shared_task(bind=True, ignore_result=True)
def poll_due_devices(self):
    """Poll every device that is due based on its configured interval."""
    now = timezone.now()

    for device in Device.objects.all():
        if _should_poll(device, now):
            _execute_poll(device)


def _generate_shift_report_csv(shift, date):
    """Generate CSV content for shift report."""
    output = StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow(['Shift Report'])
    writer.writerow(['Shift', shift.name])
    writer.writerow(['Date', date.strftime('%Y-%m-%d')])
    writer.writerow(['Time Range', f"{shift.start_time.strftime('%H:%M')} - {shift.end_time.strftime('%H:%M')}"])
    writer.writerow([])

    # Get shift reports for this shift and date
    reports = ShiftReport.objects.filter(
        shift=shift,
        date=date
    ).select_related('device')

    if reports.exists():
        writer.writerow(['Device', 'Location', 'Min PF', 'Min PF Time', 'Max PF', 'Max PF Time', 'Avg PF', 'Total kWh'])
        for report in reports:
            writer.writerow([
                report.device.device_type,
                report.device.located_at,
                f"{report.min_power_factor:.3f}",
                report.min_power_factor_time.strftime('%Y-%m-%d %H:%M:%S'),
                f"{report.max_power_factor:.3f}",
                report.max_power_factor_time.strftime('%Y-%m-%d %H:%M:%S'),
                f"{report.avg_power_factor:.3f}",
                f"{report.total_kwh:.1f}"
            ])
    else:
        writer.writerow(['No data available for this shift'])

    return output.getvalue()


def _generate_daily_report_csv(date):
    """Generate CSV content for daily report (all shifts)."""
    output = StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow(['Daily Report'])
    writer.writerow(['Date', date.strftime('%Y-%m-%d')])
    writer.writerow([])

    # Get all shifts
    shifts = Shift.objects.filter(is_active=True).order_by('start_time')

    for shift in shifts:
        writer.writerow([f'Shift: {shift.name} ({shift.start_time.strftime("%H:%M")} - {shift.end_time.strftime("%H:%M")})'])

        reports = ShiftReport.objects.filter(
            shift=shift,
            date=date
        ).select_related('device')

        if reports.exists():
            writer.writerow(['Device', 'Location', 'Min PF', 'Max PF', 'Avg PF', 'Total kWh'])
            total_kwh = 0
            for report in reports:
                writer.writerow([
                    report.device.device_type,
                    report.device.located_at,
                    f"{report.min_power_factor:.3f}",
                    f"{report.max_power_factor:.3f}",
                    f"{report.avg_power_factor:.3f}",
                    f"{report.total_kwh:.1f}"
                ])
                total_kwh += report.total_kwh
            writer.writerow(['Total', '', '', '', '', f"{total_kwh:.1f}"])
        else:
            writer.writerow(['No data available'])
        writer.writerow([])

    return output.getvalue()


@shared_task(bind=True, ignore_result=True)
def send_shift_report_email(self, shift_id, date_str):
    """Send shift report email at the end of each shift."""
    try:
        shift = Shift.objects.get(id=shift_id)
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        # Get all users who have shift_manager_email configured
        users = User.objects.filter(shift_manager_email__isnull=False).exclude(shift_manager_email='')

        if not users.exists():
            logger.warning("No users with shift_manager_email configured")
            return

        # Generate CSV report
        csv_content = _generate_shift_report_csv(shift, date)

        # Send email to each user
        for user in users:
            subject = f"Shift Report - {shift.name} - {date.strftime('%Y-%m-%d')}"
            body = f"""
Hello {user.get_full_name() or user.username},

Please find attached the shift report for:
- Shift: {shift.name}
- Date: {date.strftime('%Y-%m-%d')}
- Time: {shift.start_time.strftime('%H:%M')} - {shift.end_time.strftime('%H:%M')}

This is an automated report generated at the end of the shift.

Best regards,
Energy Meter System
            """

            email = EmailMessage(
                subject=subject,
                body=body,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[user.shift_manager_email]
            )

            # Attach CSV file
            filename = f"shift_report_{shift.name}_{date.strftime('%Y-%m-%d')}.csv"
            email.attach(filename, csv_content, 'text/csv')

            email.send(fail_silently=False)
            logger.info(f"Shift report sent to {user.shift_manager_email}")

    except Shift.DoesNotExist:
        logger.error(f"Shift with id {shift_id} does not exist")
    except Exception as e:
        logger.exception(f"Error sending shift report: {e}")


@shared_task(bind=True, ignore_result=True)
def send_daily_report_email(self, date_str):
    """Send daily report email at the end of the day (after all shifts)."""
    try:
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        # Get all users who have daily_manager_email configured
        users = User.objects.filter(daily_manager_email__isnull=False).exclude(daily_manager_email='')

        if not users.exists():
            logger.warning("No users with daily_manager_email configured")
            return

        # Generate CSV report
        csv_content = _generate_daily_report_csv(date)

        # Send email to each user
        for user in users:
            subject = f"Daily Report - {date.strftime('%Y-%m-%d')}"
            body = f"""
Hello {user.get_full_name() or user.username},

Please find attached the daily report for {date.strftime('%Y-%m-%d')}.

This report includes data from all shifts for the day.

This is an automated report generated at the end of the day.

Best regards,
Energy Meter System
            """

            email = EmailMessage(
                subject=subject,
                body=body,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[user.daily_manager_email]
            )

            # Attach CSV file
            filename = f"daily_report_{date.strftime('%Y-%m-%d')}.csv"
            email.attach(filename, csv_content, 'text/csv')

            email.send(fail_silently=False)
            logger.info(f"Daily report sent to {user.daily_manager_email}")

    except Exception as e:
        logger.exception(f"Error sending daily report: {e}")


@shared_task(bind=True, ignore_result=True)
def generate_and_send_shift_reports(self):
    """
    Generate shift reports and send emails.
    This task should run at the end of each shift.
    """
    from .views import generate_shift_reports_for_date

    try:
        today = timezone.now().date()
        current_time = timezone.localtime().time()

        # Find which shift just ended
        shifts = Shift.objects.filter(is_active=True)

        for shift in shifts:
            # Check if current time is within 5 minutes after shift end time
            end_time = shift.end_time

            # Handle shifts that cross midnight
            if shift.start_time > shift.end_time:
                # For shift that ends on next day (e.g., 20:30 to 04:30)
                if current_time < shift.start_time and current_time >= end_time:
                    # We're in the morning, shift ended today
                    target_date = today
                elif current_time >= shift.start_time:
                    # We're in the evening, shift will end tomorrow
                    target_date = today + timedelta(days=1)
                else:
                    continue
            else:
                # Normal shift within same day
                if current_time >= end_time:
                    target_date = today
                else:
                    continue

            # Check if we're within the window after shift end
            end_datetime = timezone.make_aware(datetime.combine(target_date, end_time))
            current_datetime = timezone.now()
            time_diff = (current_datetime - end_datetime).total_seconds() / 60  # minutes

            # If within 5 minutes after shift end
            if 0 <= time_diff <= 5:
                logger.info(f"Generating reports for shift {shift.name} on {target_date}")

                # Generate shift reports for this specific shift and date
                generate_shift_reports_for_date(target_date)

                # Send email with the report
                send_shift_report_email.delay(shift.id, target_date.strftime('%Y-%m-%d'))

                logger.info(f"Triggered email for shift {shift.name}")

    except Exception as e:
        logger.exception(f"Error in generate_and_send_shift_reports: {e}")


@shared_task(bind=True, ignore_result=True)
def generate_and_send_daily_report(self):
    """
    Generate daily report and send email.
    This task should run at the end of the day (after the last shift).
    """
    from .views import generate_shift_reports_for_date

    try:
        today = timezone.now().date()
        yesterday = today - timedelta(days=1)

        # Generate reports for yesterday (complete day)
        logger.info(f"Generating daily reports for {yesterday}")
        generate_shift_reports_for_date(yesterday)

        # Send daily report email
        send_daily_report_email.delay(yesterday.strftime('%Y-%m-%d'))

        logger.info(f"Triggered daily report email for {yesterday}")

    except Exception as e:
        logger.exception(f"Error in generate_and_send_daily_report: {e}")
