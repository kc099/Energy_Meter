from .models import Shift

def current_shift(request):
    """Add current shift to the context of all templates."""
    if request.user.is_authenticated:
        current_shift = Shift.get_current_shift()
        return {
            'current_shift': current_shift
        }
    return {
        'current_shift': None
    }