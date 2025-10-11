"""Celery tasks for polling device data asynchronously."""
import csv
import logging
from datetime import datetime, timedelta
from functools import update_wrapper
from io import BytesIO, StringIO
from pathlib import Path

try:
    import matplotlib

    matplotlib.use("Agg")

    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages
except Exception:  # pragma: no cover - optional dependency
    matplotlib = None
    plt = None
    PdfPages = None

try:
    from celery import shared_task
except ModuleNotFoundError:  # pragma: no cover - allow running without Celery installed
    class _ImmediateTaskWrapper:
        def __init__(self, func):
            self._func = func
            update_wrapper(self, func)

        def __call__(self, *args, **kwargs):
            return self._func(*args, **kwargs)

        def delay(self, *args, **kwargs):
            return self._func(*args, **kwargs)

        def apply_async(self, args=None, kwargs=None, **options):
            args = args or ()
            kwargs = kwargs or {}
            return self._func(*args, **kwargs)

    def shared_task(*dargs, **dkwargs):
        def decorator(func):
            wrapped = _ImmediateTaskWrapper(func)
            return wrapped

        return decorator

from django.utils import timezone
from django.core.mail import EmailMessage
from django.conf import settings

from .models import Device, Shift, ShiftReport, DeviceData
from accounts.models import ReportRecipient, User

logger = logging.getLogger(__name__)

_HAS_MATPLOTLIB = plt is not None and PdfPages is not None


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


def _get_shift_window(date, shift):
    start_datetime = timezone.make_aware(datetime.combine(date, shift.start_time))
    end_datetime = timezone.make_aware(datetime.combine(date, shift.end_time))
    if shift.start_time >= shift.end_time:
        end_datetime += timedelta(days=1)
    return start_datetime, end_datetime


def _fetch_shift_series(report):
    start_datetime, end_datetime = _get_shift_window(report.date, report.shift)
    qs = (
        DeviceData.objects.filter(
            device=report.device,
            timestamp__range=(start_datetime, end_datetime),
        )
        .order_by('timestamp')
    )
    timestamps = []
    currents = []
    voltages = []
    power_factors = []
    for entry in qs:
        payload = entry.value or {}
        try:
            currents.append(float(payload.get('current')))
            voltages.append(float(payload.get('voltage')))
            power_factors.append(float(payload.get('power_factor')))
            timestamps.append(timezone.localtime(entry.timestamp))
        except (TypeError, ValueError):
            continue
    return timestamps, currents, voltages, power_factors


def _format_timestamp(dt):
    if not dt:
        return '-'
    return timezone.localtime(dt).strftime('%Y-%m-%d %H:%M:%S')


def _shift_reports_for_period(shift, date):
    return (
        ShiftReport.objects.filter(shift=shift, date=date)
        .select_related('device')
        .order_by('device__located_at')
    )


def _daily_reports_for_period(date):
    return (
        ShiftReport.objects.filter(date=date)
        .select_related('shift', 'device')
        .order_by('shift__start_time', 'device__located_at')
    )


def _build_shift_report_pdf(shift, date):
    if not _HAS_MATPLOTLIB:
        logger.warning("matplotlib unavailable; falling back to CSV for shift report")
        return None

    reports = _shift_reports_for_period(shift, date)
    if not reports:
        return None

    buffer = BytesIO()
    with PdfPages(buffer) as pdf:
        for report in reports:
            timestamps, currents, voltages, power_factors = _fetch_shift_series(report)

            fig = plt.figure(figsize=(8.27, 11.69))  # A4 portrait
            fig.suptitle(
                f"Shift Report: {shift.name} – {report.device.located_at}\n{date.strftime('%Y-%m-%d')}",
                fontsize=14,
                fontweight='bold',
                y=0.97,
            )
            gs = fig.add_gridspec(3, 1, height_ratios=[0.4, 2.6, 2.0])

            ax_title = fig.add_subplot(gs[0])
            ax_title.axis('off')
            ax_title.text(
                0,
                0.5,
                (
                    f"Device ID: {report.device.id}\n"
                    f"Energy consumed: {report.total_kwh:.2f} kWh\n"
                    f"Data points logged: {report.data_points}"
                ),
                fontsize=11,
                va='center',
            )

            ax_graph = fig.add_subplot(gs[1])
            if timestamps:
                ax_graph.plot(timestamps, currents, label='Current (A)', color='#1f77b4')
                ax_graph.set_ylabel('Current (A)')
                ax_graph.tick_params(axis='x', rotation=30)

                ax_voltage = ax_graph.twinx()
                ax_voltage.plot(
                    timestamps,
                    voltages,
                    label='Voltage (V)',
                    color='#ff7f0e',
                )
                ax_voltage.set_ylabel('Voltage (V)')

                if power_factors:
                    ax_pf = ax_graph.twinx()
                    ax_pf.spines['right'].set_position(('outward', 60))
                    ax_pf.plot(
                        timestamps,
                        power_factors,
                        label='Power Factor',
                        color='#2ca02c',
                    )
                    ax_pf.set_ylabel('Power Factor')

                ax_graph.set_xlabel('Timestamp')
                ax_graph.grid(True, linestyle='--', alpha=0.5)
            else:
                ax_graph.axis('off')
                ax_graph.text(
                    0.5,
                    0.5,
                    'No telemetry samples available during this shift.',
                    ha='center',
                    va='center',
                    fontsize=12,
                    color='gray',
                )

            ax_table = fig.add_subplot(gs[2])
            ax_table.axis('off')
            table_data = [
                ('Min Power Factor', f"{report.min_power_factor:.3f}", _format_timestamp(report.min_power_factor_time)),
                ('Max Power Factor', f"{report.max_power_factor:.3f}", _format_timestamp(report.max_power_factor_time)),
                ('Avg Power Factor', f"{report.avg_power_factor:.3f}", ''),
                ('Min Current (A)', f"{report.min_current:.3f}", _format_timestamp(report.min_current_time)),
                ('Max Current (A)', f"{report.max_current:.3f}", _format_timestamp(report.max_current_time)),
                ('Avg Current (A)', f"{report.avg_current:.3f}", ''),
                ('Min Voltage (V)', f"{report.min_voltage:.2f}", _format_timestamp(report.min_voltage_time)),
                ('Max Voltage (V)', f"{report.max_voltage:.2f}", _format_timestamp(report.max_voltage_time)),
                ('Avg Voltage (V)', f"{report.avg_voltage:.2f}", ''),
            ]
            col_labels = ['Metric', 'Value', 'Timestamp']
            table = ax_table.table(
                cellText=table_data,
                colLabels=col_labels,
                loc='center',
                cellLoc='center',
            )
            table.auto_set_font_size(False)
            table.set_fontsize(9)
            table.scale(1, 1.3)

            pdf.savefig(fig, bbox_inches='tight')
            plt.close(fig)

    return buffer.getvalue()


def _build_daily_report_pdf(date):
    if not _HAS_MATPLOTLIB:
        logger.warning("matplotlib unavailable; falling back to CSV for daily report")
        return None

    reports = _daily_reports_for_period(date)
    if not reports:
        return None

    buffer = BytesIO()
    with PdfPages(buffer) as pdf:
        fig = plt.figure(figsize=(8.27, 11.69))
        fig.suptitle(
            f"Daily Report – {date.strftime('%Y-%m-%d')}",
            fontsize=16,
            fontweight='bold',
            y=0.97,
        )

        gs = fig.add_gridspec(3, 1, height_ratios=[0.6, 2.2, 2.2])

        ax_summary = fig.add_subplot(gs[0])
        ax_summary.axis('off')
        total_energy = sum(report.total_kwh for report in reports)
        ax_summary.text(
            0,
            0.5,
            f"Total energy consumed across all shifts: {total_energy:.2f} kWh",
            fontsize=12,
        )

        ax_bar = fig.add_subplot(gs[1])
        shift_labels = []
        energy_values = []
        for report in reports:
            label = f"{report.shift.name}\n{report.device.located_at}"
            shift_labels.append(label)
            energy_values.append(report.total_kwh)
        ax_bar.bar(shift_labels, energy_values, color='#1f77b4')
        ax_bar.set_ylabel('Energy (kWh)')
        ax_bar.set_title('Shift-wise Energy Consumption')
        ax_bar.tick_params(axis='x', rotation=45, ha='right')
        ax_bar.grid(axis='y', linestyle='--', alpha=0.5)

        ax_table = fig.add_subplot(gs[2])
        ax_table.axis('off')
        table_rows = []
        for report in reports:
            table_rows.append([
                report.shift.name,
                report.device.located_at,
                f"{report.min_power_factor:.3f}",
                f"{report.max_power_factor:.3f}",
                f"{report.min_current:.3f}",
                f"{report.max_current:.3f}",
                f"{report.min_voltage:.2f}",
                f"{report.max_voltage:.2f}",
                f"{report.total_kwh:.1f}",
            ])

        table = ax_table.table(
            cellText=table_rows,
            colLabels=[
                'Shift',
                'Device',
                'Min PF',
                'Max PF',
                'Min Current (A)',
                'Max Current (A)',
                'Min Voltage (V)',
                'Max Voltage (V)',
                'Energy (kWh)',
            ],
            loc='center',
            cellLoc='center',
        )
        table.auto_set_font_size(False)
        table.set_fontsize(8)
        table.scale(1, 1.3)

        pdf.savefig(fig, bbox_inches='tight')
        plt.close(fig)

    return buffer.getvalue()


def _csv_rows_for_report(report):
    return [
        report.shift.name,
        report.device.located_at,
        f"{report.total_kwh:.2f}",
        f"{report.min_power_factor:.3f}",
        report.min_power_factor_time.strftime('%Y-%m-%d %H:%M:%S') if report.min_power_factor_time else '-',
        f"{report.max_power_factor:.3f}",
        report.max_power_factor_time.strftime('%Y-%m-%d %H:%M:%S') if report.max_power_factor_time else '-',
        f"{report.avg_power_factor:.3f}",
        f"{report.min_current:.3f}",
        report.min_current_time.strftime('%Y-%m-%d %H:%M:%S') if report.min_current_time else '-',
        f"{report.max_current:.3f}",
        report.max_current_time.strftime('%Y-%m-%d %H:%M:%S') if report.max_current_time else '-',
        f"{report.avg_current:.3f}",
        f"{report.min_voltage:.2f}",
        report.min_voltage_time.strftime('%Y-%m-%d %H:%M:%S') if report.min_voltage_time else '-',
        f"{report.max_voltage:.2f}",
        report.max_voltage_time.strftime('%Y-%m-%d %H:%M:%S') if report.max_voltage_time else '-',
        f"{report.avg_voltage:.2f}",
        report.data_points,
    ]


def _generate_shift_report_csv(shift, date):
    reports = list(_shift_reports_for_period(shift, date))
    if not reports:
        return None

    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            'Shift',
            'Device Location',
            'Energy (kWh)',
            'Min PF',
            'Min PF Time',
            'Max PF',
            'Max PF Time',
            'Avg PF',
            'Min Current (A)',
            'Min Current Time',
            'Max Current (A)',
            'Max Current Time',
            'Avg Current (A)',
            'Min Voltage (V)',
            'Min Voltage Time',
            'Max Voltage (V)',
            'Max Voltage Time',
            'Avg Voltage (V)',
            'Data Points',
        ]
    )
    for report in reports:
        writer.writerow(_csv_rows_for_report(report))
    return buffer.getvalue().encode('utf-8')


def _generate_daily_report_csv(date):
    reports = list(_daily_reports_for_period(date))
    if not reports:
        return None

    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            'Shift',
            'Device Location',
            'Energy (kWh)',
            'Min PF',
            'Min PF Time',
            'Max PF',
            'Max PF Time',
            'Avg PF',
            'Min Current (A)',
            'Min Current Time',
            'Max Current (A)',
            'Max Current Time',
            'Avg Current (A)',
            'Min Voltage (V)',
            'Min Voltage Time',
            'Max Voltage (V)',
            'Max Voltage Time',
            'Avg Voltage (V)',
            'Data Points',
        ]
    )
    for report in reports:
        writer.writerow(_csv_rows_for_report(report))
    return buffer.getvalue().encode('utf-8')


def _collect_shift_recipients(shift):
    """Return a list of (owner, email, recipient) tuples for shift reports."""
    seen = set()
    results = []

    recipients = (
        ReportRecipient.objects.filter(
            send_shift_reports=True,
            shifts=shift,
        )
        .select_related('user')
        .distinct()
    )
    for recipient in recipients:
        email = (recipient.email or '').strip()
        if not email:
            continue
        lower = email.lower()
        if lower in seen:
            continue
        seen.add(lower)
        results.append((recipient.user, email, recipient))

    # Fallback to legacy single-email fields if no dedicated recipients exist.
    if not results:
        legacy_users = User.objects.filter(shift_manager_email__isnull=False).exclude(
            shift_manager_email=''
        )
        for user in legacy_users:
            email = (user.shift_manager_email or '').strip()
            if not email:
                continue
            lower = email.lower()
            if lower in seen:
                continue
            seen.add(lower)
            results.append((user, email, None))

    return results


def _collect_daily_recipients():
    """Return a list of (owner, email, recipient) tuples for daily reports."""
    seen = set()
    results = []

    recipients = (
        ReportRecipient.objects.filter(send_daily_reports=True)
        .select_related('user')
        .distinct()
    )
    for recipient in recipients:
        email = (recipient.email or '').strip()
        if not email:
            continue
        lower = email.lower()
        if lower in seen:
            continue
        seen.add(lower)
        results.append((recipient.user, email, recipient))

    if not results:
        legacy_users = User.objects.filter(daily_manager_email__isnull=False).exclude(
            daily_manager_email=''
        )
        for user in legacy_users:
            email = (user.daily_manager_email or '').strip()
            if not email:
                continue
            lower = email.lower()
            if lower in seen:
                continue
            seen.add(lower)
            results.append((user, email, None))

    return results


def _store_daily_report_offline(payload, filename):
    reports_dir = Path.home() / "Documents" / "reports"
    file_path = reports_dir / filename

    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
        with file_path.open("wb") as offline_file:
            offline_file.write(payload)
    except Exception:  # pragma: no cover - filesystem availability differs per deploy
        logger.exception("Failed to store daily report offline at %s", reports_dir)
        return None

    logger.info("Stored daily report at %s", file_path)
    return file_path


def _mark_recipient_success(recipient):
    if not recipient:
        return
    recipient.last_success_at = timezone.now()
    recipient.last_failure_at = None
    recipient.last_failure_message = ''
    recipient.save(update_fields=['last_success_at', 'last_failure_at', 'last_failure_message'])


def _mark_recipient_failure(recipient, error):
    if not recipient:
        return
    recipient.last_failure_at = timezone.now()
    recipient.last_failure_message = str(error)[:1000]
    recipient.save(update_fields=['last_failure_at', 'last_failure_message'])


@shared_task(bind=True, ignore_result=True)
def send_shift_report_email(self, shift_id, date_str):
    """Send shift report email at the end of each shift."""
    try:
        shift = Shift.objects.get(id=shift_id)
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        recipients = _collect_shift_recipients(shift)

        if not recipients:
            logger.warning("No recipients configured for shift reports")
            return

        pdf_content = _build_shift_report_pdf(shift, date)

        attachment_payload = None
        attachment_name = None
        attachment_mime = None

        if pdf_content:
            attachment_payload = pdf_content
            attachment_name = f"shift_report_{shift.name}_{date.strftime('%Y-%m-%d')}.pdf"
            attachment_mime = 'application/pdf'
        else:
            csv_content = _generate_shift_report_csv(shift, date)
            if not csv_content:
                logger.warning("No shift data available for %s on %s", shift.name, date)
                return
            attachment_payload = csv_content
            attachment_name = f"shift_report_{shift.name}_{date.strftime('%Y-%m-%d')}.csv"
            attachment_mime = 'text/csv'

        # Send email to each user
        start_label = shift.start_time.strftime('%I:%M %p').lstrip('0').lower()
        end_label = shift.end_time.strftime('%I:%M %p').lstrip('0').lower()
        for owner, email_address, recipient_obj in recipients:
            subject = f"Shift Report - {shift.name} - {date.strftime('%Y-%m-%d')}"
            body = f"""
Hello {owner.get_full_name() or owner.username},

Please find attached the shift report for:
- Shift: {shift.name}
- Date: {date.strftime('%Y-%m-%d')}
- Time: {start_label} - {end_label}

This is an automated report generated at the end of the shift.

Best regards,
Energy Meter System
            """

            email = EmailMessage(
                subject=subject,
                body=body,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[email_address]
            )
            email.attach(attachment_name, attachment_payload, attachment_mime)

            try:
                email.send(fail_silently=False)
            except Exception as exc:
                _mark_recipient_failure(recipient_obj, exc)
                raise
            else:
                _mark_recipient_success(recipient_obj)
                logger.info("Shift report sent to %s", email_address)

    except Shift.DoesNotExist:
        logger.error(f"Shift with id {shift_id} does not exist")
    except Exception as e:
        logger.exception(f"Error sending shift report: {e}")


@shared_task(bind=True, ignore_result=True)
def send_daily_report_email(self, date_str):
    """Send daily report email at the end of the day (after all shifts)."""
    try:
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        recipients = _collect_daily_recipients()

        pdf_content = _build_daily_report_pdf(date)

        attachment_payload = None
        attachment_name = None
        attachment_mime = None

        if pdf_content:
            attachment_payload = pdf_content
            attachment_name = f"daily_report_{date.strftime('%Y-%m-%d')}.pdf"
            attachment_mime = 'application/pdf'
        else:
            csv_content = _generate_daily_report_csv(date)
            if not csv_content:
                logger.warning("No daily report data available for %s", date)
                return
            attachment_payload = csv_content
            attachment_name = f"daily_report_{date.strftime('%Y-%m-%d')}.csv"
            attachment_mime = 'text/csv'

        offline_path = _store_daily_report_offline(attachment_payload, attachment_name)

        if not recipients:
            if offline_path:
                logger.warning(
                    "No recipients configured for daily reports; stored offline at %s",
                    offline_path,
                )
            else:
                logger.warning(
                    "No recipients configured for daily reports and offline storage failed",
                )
            return

        # Send email to each user
        for owner, email_address, recipient_obj in recipients:
            subject = f"Daily Report - {date.strftime('%Y-%m-%d')}"
            body = f"""
Hello {owner.get_full_name() or owner.username},

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
                to=[email_address]
            )
            email.attach(attachment_name, attachment_payload, attachment_mime)

            try:
                email.send(fail_silently=False)
            except Exception as exc:
                _mark_recipient_failure(recipient_obj, exc)
                raise
            else:
                _mark_recipient_success(recipient_obj)
                logger.info("Daily report sent to %s", email_address)

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
