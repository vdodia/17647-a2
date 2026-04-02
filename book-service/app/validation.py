"""
validation.py – Shared input validation helpers.
Per assignment spec: do NOT validate ISBN, zip codes, or phone numbers.
"""
import re
from decimal import Decimal, InvalidOperation

# All valid US state abbreviations (50 states + DC)
VALID_US_STATES = {
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA",
    "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD",
    "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ",
    "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC",
    "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY",
    "DC",
}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_price(value) -> bool:
    """Return True if value is a valid number with 0-2 decimal places."""
    try:
        d = Decimal(str(value))
    except InvalidOperation:
        return False
    if d < Decimal('0'):
        return False
    sign, digits, exponent = d.as_tuple()
    # exponent is negative for decimal places; abs(exponent) is the # of dp
    return exponent >= -2


def validate_email(value: str) -> bool:
    """Return True if value looks like a valid email address."""
    return bool(EMAIL_RE.match(value))


def validate_state(value: str) -> bool:
    """Return True if value is a valid 2-letter US state abbreviation."""
    return isinstance(value, str) and value.upper() in VALID_US_STATES


def check_required_fields(data: dict, required: list) -> list:
    """Return list of field names that are missing or None in data."""
    missing = []
    for field in required:
        if field not in data or data[field] is None:
            missing.append(field)
    return missing
