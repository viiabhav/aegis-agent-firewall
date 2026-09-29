from __future__ import annotations

import json
from typing import Any


def extract_api_text(payload: Any) -> tuple[str, dict]:
    if isinstance(payload, str):
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            return payload, {"format": "string"}
        return json.dumps(parsed, ensure_ascii=False, indent=2, sort_keys=True), {"format": "json"}

    try:
        text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str)
    except TypeError as exc:
        raise ValueError("API payload is not serializable") from exc
    return text, {"format": "json"}
