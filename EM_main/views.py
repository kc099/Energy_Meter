import csv
from datetime import date, datetime
from io import BytesIO

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Avg, Min, Max, Sum, Q
from django.http import HttpResponse
from django.shortcuts import render
from django.utils import timezone

from devices.models import DeviceData, ShiftReport

DATE_INPUT_FORMAT = "%Y-%m-%d"


READINGS_SORT_CHOICES = [
    ('timestamp_asc', 'Timestamp (Oldest first)'),
    ('timestamp_desc', 'Timestamp (Newest first)'),
]

READINGS_SORT_DEFAULT = 'timestamp_desc'
READINGS_ORDER_MAP = {
    'timestamp_asc': 'timestamp',
    'timestamp_desc': '-timestamp',
}

MINMAX_SORT_CHOICES = [
    ('date_desc', 'Date (Newest first)'),
    ('date_asc', 'Date (Oldest first)'),
    ('min_pf_desc', 'Min PF (Highest first)'),
    ('min_pf_asc', 'Min PF (Lowest first)'),
    ('max_pf_desc', 'Max PF (Highest first)'),
    ('max_pf_asc', 'Max PF (Lowest first)'),
    ('avg_pf_desc', 'Avg PF (Highest first)'),
    ('avg_pf_asc', 'Avg PF (Lowest first)'),
]

MINMAX_SORT_DEFAULT = 'date_desc'
MINMAX_ORDER_MAP = {
    'date_desc': ['-date', '-shift__start_time'],
    'date_asc': ['date', 'shift__start_time'],
    'min_pf_desc': ['-min_pf', '-date', '-shift__start_time'],
    'min_pf_asc': ['min_pf', 'date', 'shift__start_time'],
    'max_pf_desc': ['-max_pf', '-date', '-shift__start_time'],
    'max_pf_asc': ['max_pf', 'date', 'shift__start_time'],
    'avg_pf_desc': ['-avg_pf', '-date', '-shift__start_time'],
    'avg_pf_asc': ['avg_pf', 'date', 'shift__start_time'],
}


def _normalize_dataset(key: str) -> str:
    if not key:
        return 'readings'
    key = key.strip().lower()
    if key == 'minmax':
        return 'minmax'
    return 'readings'


def _normalize_sort(dataset_key: str, sort_key: str) -> str:
    dataset_key = _normalize_dataset(dataset_key)
    sort_key = (sort_key or '').strip().lower()
    if dataset_key == 'minmax':
        valid = {choice for choice, _ in MINMAX_SORT_CHOICES}
        default = MINMAX_SORT_DEFAULT
    else:
        valid = {choice for choice, _ in READINGS_SORT_CHOICES}
        default = READINGS_SORT_DEFAULT
    return sort_key if sort_key in valid else default


def home(request):
    return render(request, 'home/index.html')


def _parse_date(value: str) -> date:
    if not value:
        raise ValueError('Select both From and To dates before downloading.')
    try:
        return datetime.strptime(value, DATE_INPUT_FORMAT).date()
    except ValueError:
        raise ValueError('Dates must be provided in YYYY-MM-DD format.')


def _validated_date_range(from_value: str, to_value: str):
    start_date = _parse_date(from_value)
    end_date = _parse_date(to_value)
    if start_date > end_date:
        raise ValueError('From date must be before or equal to To date.')
    return start_date, end_date


def _format_datetime(value):
    if not value:
        return ''
    return timezone.localtime(value).strftime('%Y-%m-%d %H:%M')


def _format_float(value):
    if value is None:
        return ''
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return str(value)
    return f'{numeric:.3f}'


def _stringify(value):
    if value is None:
        return ''
    return str(value)


def _format_table_lines(headers, rows):
    headers = [str(h) for h in headers]
    str_rows = []
    for row in rows:
        str_row = []
        for value in row:
            str_row.append(_stringify(value))
        str_rows.append(str_row)

    widths = [len(header) for header in headers]
    for row in str_rows:
        for idx, value in enumerate(row):
            if idx >= len(widths):
                widths.append(len(value))
            else:
                widths[idx] = max(widths[idx], len(value))
    if len(widths) < len(headers):
        widths.extend(len(headers[idx]) for idx in range(len(widths), len(headers)))

    def _format_row(values):
        padded = []
        for idx, value in enumerate(values):
            width = widths[idx] if idx < len(widths) else len(value)
            padded.append(value.ljust(width))
        return ' | '.join(padded)

    header_line = _format_row(headers)
    separator_line = '-+-'.join('-' * width for width in widths)
    data_lines = [_format_row(row) for row in str_rows]
    return [header_line, separator_line, *data_lines]


def _escape_pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")



def _compose_simple_pdf(lines, repeat_from=None, repeat_length=0):
    lines_per_page = 58
    header_lines = []
    if repeat_from is not None and repeat_length:
        header_lines = lines[repeat_from:repeat_from + repeat_length]

    pages = []
    current_page = []
    for line in lines:
        if len(current_page) >= lines_per_page:
            pages.append(current_page)
            current_page = header_lines.copy() if header_lines else []
        current_page.append(line)
    if current_page:
        pages.append(current_page)

    if not pages:
        pages = [[]]

    pdf_objects = []
    catalog_obj = b'<< /Type /Catalog /Pages 2 0 R >>'
    pdf_objects.append(catalog_obj)

    num_pages = len(pages)
    page_ids = [3 + i * 2 for i in range(num_pages)]
    kids = ' '.join(f'{page_id} 0 R' for page_id in page_ids)
    pages_obj = f'<< /Type /Pages /Kids [{kids}] /Count {num_pages} >>'.encode('ascii')
    pdf_objects.append(pages_obj)

    font_obj_id = 3 + num_pages * 2

    for idx, page_lines in enumerate(pages):
        text_commands = [
            b'BT',
            b'/F1 10 Tf',
            b'12 TL',
            b'72 780 Td',
        ]
        for line in page_lines:
            text_commands.append(f'({_escape_pdf_text(line)}) Tj'.encode('utf-8'))
            text_commands.append(b'T*')
        if text_commands[-1] == b'T*':
            text_commands.pop()
        text_commands.append(b'ET')
        text_stream = b'\n'.join(text_commands)

        content_body = b'<< /Length %d >>\nstream\n%s\nendstream' % (len(text_stream), text_stream)
        pdf_objects.append(
            f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {page_ids[idx] + 1} 0 R /Resources << /Font << /F1 {font_obj_id} 0 R >> >> >>'.encode('ascii')
        )
        pdf_objects.append(content_body)

    font_body = b'<< /Type /Font /Subtype /Type1 /Name /F1 /BaseFont /Courier >>'
    pdf_objects.append(font_body)

    buffer = BytesIO()
    buffer.write(b'%PDF-1.4\n')

    offsets = [0]
    for index, body in enumerate(pdf_objects, start=1):
        offsets.append(buffer.tell())
        buffer.write(f'{index} 0 obj\n'.encode('ascii'))
        buffer.write(body)
        buffer.write(b'\nendobj\n')

    xref_position = buffer.tell()
    total_objects = len(pdf_objects) + 1
    buffer.write(f'xref\n0 {total_objects}\n'.encode('ascii'))
    buffer.write(b'0000000000 65535 f \n')
    for offset in offsets[1:]:
        buffer.write(f'{offset:010d} 00000 n \n'.encode('ascii'))
    buffer.write(b'trailer\n')
    buffer.write(f'<< /Size {total_objects} /Root 1 0 R >>\n'.encode('ascii'))
    buffer.write(b'startxref\n')
    buffer.write(f'{xref_position}\n'.encode('ascii'))
    buffer.write(b'%%EOF')

    return buffer.getvalue()

def _device_access_q(user):
    if getattr(user, 'is_superuser', False):
        return Q()
    return Q(device__device_owner=user) | Q(device__shared_with=user)


def _meter_reading_rows(user, start_date, end_date, limit=None, offset=0, sort_key=None):
    order_by_field = READINGS_ORDER_MAP.get(sort_key, READINGS_ORDER_MAP[READINGS_SORT_DEFAULT])
    queryset = (
        DeviceData.objects.filter(
            _device_access_q(user),
            timestamp__date__range=(start_date, end_date),
        )
        .select_related('device')
        .order_by(order_by_field)
    )
    total_count = queryset.count()

    if offset < 0:
        offset = 0

    if limit is not None:
        queryset = queryset[offset:offset + limit]
    elif offset:
        queryset = queryset[offset:]

    rows = []
    for record in queryset:
        value = record.value or {}
        rows.append([
            _format_datetime(record.timestamp),
            record.device.located_at,
            _stringify(value.get('voltage')),
            _stringify(value.get('current')),
            _stringify(value.get('power_factor')),
            _stringify(value.get('kwh')),
            _stringify(value.get('kwah')),
        ])
    return rows, total_count


def _minmax_summary_rows(user, start_date, end_date, limit=None, offset=0, sort_key=None):
    order_fields = MINMAX_ORDER_MAP.get(sort_key, MINMAX_ORDER_MAP[MINMAX_SORT_DEFAULT])
    queryset = (
        ShiftReport.objects.filter(
            _device_access_q(user),
            date__range=(start_date, end_date),
        )
        .values('date', 'shift__name', 'shift__start_time')
        .annotate(
            min_pf=Min('min_power_factor'),
            max_pf=Max('max_power_factor'),
            avg_pf=Avg('avg_power_factor'),
            total_kwh=Sum('total_kwh'),
        )
        .order_by(*order_fields)
    )
    total_count = queryset.count()

    if offset < 0:
        offset = 0

    if limit is not None:
        queryset = queryset[offset:offset + limit]
    elif offset:
        queryset = queryset[offset:]

    rows = []
    for entry in queryset:
        rows.append([
            entry['date'].strftime('%Y-%m-%d'),
            entry['shift__name'],
            _format_float(entry['min_pf']),
            _format_float(entry['max_pf']),
            _format_float(entry['avg_pf']),
            _stringify(entry['total_kwh']),
        ])
    return rows, total_count


def _build_preview_data(user, dataset_key, start_date, end_date, *, page=1, page_size=10, sort_key=None):
    dataset_key = _normalize_dataset(dataset_key)
    sort_key = _normalize_sort(dataset_key, sort_key)
    try:
        page = int(page)
    except (TypeError, ValueError):
        page = 1
    if page < 1:
        page = 1

    if dataset_key == 'readings':
        offset = (page - 1) * page_size
        rows, total = _meter_reading_rows(
            user, start_date, end_date, limit=page_size, offset=offset, sort_key=sort_key
        )
        total_pages = max(1, (total + page_size - 1) // page_size) if total else 1
        if total and page > total_pages:
            page = total_pages
            offset = (page - 1) * page_size
            rows, _ = _meter_reading_rows(
                user, start_date, end_date, limit=page_size, offset=offset, sort_key=sort_key
            )
        headers = ['Timestamp', 'Location', 'Voltage', 'Current', 'Power Factor', 'kWh', 'kWAH']

    elif dataset_key == 'minmax':
        offset = (page - 1) * page_size
        rows, total = _minmax_summary_rows(
            user, start_date, end_date, limit=page_size, offset=offset, sort_key=sort_key
        )
        total_pages = max(1, (total + page_size - 1) // page_size) if total else 1
        if total and page > total_pages:
            page = total_pages
            offset = (page - 1) * page_size
            rows, _ = _minmax_summary_rows(
                user, start_date, end_date, limit=page_size, offset=offset, sort_key=sort_key
            )
        headers = ['Date', 'Shift', 'Min PF', 'Max PF', 'Avg PF', 'Total kWh']

    else:
        return None

    if total == 0:
        page = 1
        offset = 0

    start_row = offset + 1 if total else 0
    end_row = offset + len(rows)
    has_prev = total > 0 and page > 1
    has_next = total > end_row

    return {
        'title': 'Meter Readings Preview' if dataset_key == 'readings' else 'Min/Max Summary Preview',
        'headers': headers,
        'rows': rows,
        'total_rows': total,
        'page': page,
        'page_size': page_size,
        'total_pages': total_pages,
        'has_prev': has_prev,
        'has_next': has_next,
        'prev_page': page - 1 if has_prev else page,
        'next_page': page + 1 if has_next else page,
        'start_row': start_row,
        'end_row': end_row,
        'is_truncated': has_prev or has_next,
        'sort': sort_key,
        'dataset': dataset_key,
    }


def _build_csv_response(filename_base, headers, rows):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{filename_base}.csv"'
    writer = csv.writer(response)
    writer.writerow(headers)
    for row in rows:
        writer.writerow(row)
    return response


def _build_pdf_response(filename_base, title, headers, rows, start_date, end_date):
    lines = [title, f'Date range: {start_date:%Y-%m-%d} to {end_date:%Y-%m-%d}', '']
    table_lines = _format_table_lines(headers, rows if rows else [])
    lines.extend(table_lines)
    if not rows:
        lines.append('')
        lines.append('No data available for the selected filters.')

    repeat_from = 2 if rows else None
    repeat_length = 3 if rows else 0

    pdf_bytes = _compose_simple_pdf(lines, repeat_from=repeat_from, repeat_length=repeat_length)
    response = HttpResponse(pdf_bytes, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename_base}.pdf"'
    return response


def _build_report_response(user, dataset_key, export_format, start_date, end_date, sort_key=None):
    dataset_key = _normalize_dataset(dataset_key)
    sort_key = _normalize_sort(dataset_key, sort_key)
    export_format = (export_format or '').strip().lower()

    if dataset_key == 'readings':
        rows, _ = _meter_reading_rows(
            user, start_date, end_date, sort_key=sort_key
        )
        headers = ['Timestamp', 'Location', 'Voltage', 'Current', 'Power Factor', 'kWh', 'kWAH']
        title = 'Meter Readings'
        filename_base = f'meter-readings-{start_date:%Y%m%d}-{end_date:%Y%m%d}'

    elif dataset_key == 'minmax':
        rows, _ = _minmax_summary_rows(
            user, start_date, end_date, sort_key=sort_key
        )
        headers = ['Date', 'Shift', 'Min PF', 'Max PF', 'Avg PF', 'Total kWh']
        title = 'Min/Max Summary'
        filename_base = f'minmax-summary-{start_date:%Y%m%d}-{end_date:%Y%m%d}'

    else:
        raise ValueError('Select a valid data set before downloading.')

    if not rows:
        raise ValueError('No data found for the selected filters.')

    if export_format == 'csv':
        return _build_csv_response(filename_base, headers, rows)
    if export_format == 'pdf':
        return _build_pdf_response(filename_base, title, headers, rows, start_date, end_date)

    raise ValueError('Select a valid export format before downloading.')


@login_required
def reports(request):
    minmax_stats = ShiftReport.objects.filter(
        _device_access_q(request.user)
    ).aggregate(
        overall_min=Min('min_power_factor'),
        overall_max=Max('max_power_factor'),
    )

    page_param = request.GET.get('page', '1')
    try:
        current_page = int(page_param)
    except (TypeError, ValueError):
        current_page = 1
    if current_page < 1:
        current_page = 1

    raw_dataset = request.GET.get('dataset', '')
    dataset_key = _normalize_dataset(raw_dataset)
    sort_param = request.GET.get('sort')
    sort_key = _normalize_sort(dataset_key, sort_param)

    form_values = {
        'dataset': raw_dataset,
        'export_format': request.GET.get('format', 'csv') or 'csv',
        'from_date': request.GET.get('from', ''),
        'to_date': request.GET.get('to', ''),
        'page': str(current_page),
        'sort': sort_key,
    }

    preview_data = None
    action = request.GET.get('action')

    if action in {'preview', 'download'}:
        if all(request.GET.get(param) for param in ('dataset', 'format', 'from', 'to')):
            try:
                start_date, end_date = _validated_date_range(request.GET.get('from'), request.GET.get('to'))
                export_format = request.GET.get('format')

                if action == 'download':
                    return _build_report_response(
                        request.user,
                        dataset_key,
                        export_format,
                        start_date,
                        end_date,
                        sort_key=sort_key,
                    )

                preview_data = _build_preview_data(
                    request.user,
                    dataset_key,
                    start_date,
                    end_date,
                    page=current_page,
                    sort_key=sort_key,
                )
                if preview_data is None:
                    messages.error(request, 'Select a valid data set before downloading.')
                else:
                    form_values['dataset'] = preview_data['dataset']
                    form_values['sort'] = preview_data['sort']
                    form_values['page'] = str(preview_data['page'])

            except ValueError as error:
                messages.error(request, str(error))
        elif action == 'download':
            messages.error(request, 'Fill out all filters before downloading.')

    sort_choices = MINMAX_SORT_CHOICES if dataset_key == 'minmax' else READINGS_SORT_CHOICES

    context = {
        'form_values': form_values,
        'preview_data': preview_data,
        'minmax_stats': minmax_stats,
        'sort_choices': sort_choices,
        'normalized_dataset': dataset_key,
    }
    return render(request, 'reports/index.html', context)
