"""Shared pagination bounds for API-driven list screens."""

DEFAULT_PAGE_SIZE = 100
PAGE_SIZE_OPTIONS = (100, 500, 1000)
MAX_PAGE_SIZE = max(PAGE_SIZE_OPTIONS)


def page_count(total: int, page_size: int) -> int:
    """Return at least one page for a paginated response."""
    return max(1, (total + page_size - 1) // page_size)
