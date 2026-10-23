"""Tenant-aware formatting for cent values shown to people."""

from decimal import ROUND_HALF_UP, Decimal


def format_cents(cents: int | float | None, currency: str = "CAD") -> str:
    code = str(currency or "CAD").upper()
    dollars = Decimal(str(cents or 0)) / Decimal("100")
    rounded = dollars.quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    symbol = "$" if code == "USD" else "CA$" if code == "CAD" else code
    return f"{symbol}{rounded:,.0f}"
