import re
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ParsedCode:
    code: str
    received_at: datetime


def parse_patterns(raw_patterns: str) -> list[str]:
    return [line.strip() for line in raw_patterns.splitlines() if line.strip()]


def extract_code(
    body: str,
    patterns: list[str],
    sender: str | None = None,
    subject: str | None = None,
    sender_filter: str | None = None,
    subject_filter: str | None = None,
) -> str | None:
    if sender_filter and sender and sender_filter.lower() not in sender.lower():
        return None
    if subject_filter and subject and subject_filter.lower() not in subject.lower():
        return None

    for pattern in patterns:
        match = re.search(pattern, body, flags=re.MULTILINE)
        if match:
            return match.group(1) if match.groups() else match.group(0)
    return None
