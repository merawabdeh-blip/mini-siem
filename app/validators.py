import re
import html


MAX_MESSAGE_LENGTH = 500


def sanitize_text(text: str) -> str:
    if text is None:
        return ""

    text = str(text).strip()

    # إزالة المسافات الزائدة
    text = re.sub(r"\s+", " ", text)

    # escape HTML characters
    text = html.escape(text)

    return text


def is_valid_ip(ip: str) -> bool:
    if not ip:
        return False

    pattern = r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
    return re.match(pattern, ip) is not None


def validate_log_input(log: dict):
    if not isinstance(log, dict):
        return False, "Log must be a JSON object"

    message = sanitize_text(log.get("message", ""))
    source = sanitize_text(log.get("source", ""))
    source_ip = sanitize_text(log.get("source_ip", ""))

    if not message:
        return False, "Message cannot be empty"

    if len(message) > MAX_MESSAGE_LENGTH:
        return False, f"Message too long (max {MAX_MESSAGE_LENGTH} chars)"

    if message.isdigit():
        return False, "Numeric-only messages are not allowed"

    if source and len(source) > 50:
        return False, "Source too long"

    if source_ip and not is_valid_ip(source_ip):
        return False, "Invalid source_ip format"

    sanitized_log = {
        "message": message,
        "source": source if source else "unknown",
        "source_ip": source_ip
    }

    return True, sanitized_log
