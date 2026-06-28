import json
import os
import urllib.error
import urllib.request

BUNDLED_STATS_FILE = os.path.join(os.path.dirname(__file__), "stats.json")
STATS_REDIS_KEY = "phishzero:stats"

_STATS_CACHE = None


def _default_stats():
    return {
        "today_scans": 124,
        "threats_detected": 42,
        "safe_urls": 82,
        "qr_scans": 15,
        "average_risk_score": 38.0,
    }


def _is_serverless():
    return bool(
        os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    )


def _use_upstash():
    return bool(
        os.environ.get("UPSTASH_REDIS_REST_URL")
        and os.environ.get("UPSTASH_REDIS_REST_TOKEN")
    )


def _writable_stats_file():
    if _is_serverless():
        return "/tmp/phishzero_stats.json"
    return BUNDLED_STATS_FILE


def _normalize_stats(stats):
    normalized = {**_default_stats(), **stats}
    normalized["today_scans"] = max(
        int(normalized.get("today_scans", 0)),
        int(normalized.get("threats_detected", 0))
        + int(normalized.get("safe_urls", 0)),
    )
    normalized["threats_detected"] = int(normalized.get("threats_detected", 0))
    normalized["safe_urls"] = int(normalized.get("safe_urls", 0))
    normalized["qr_scans"] = int(normalized.get("qr_scans", 0))
    normalized["average_risk_score"] = float(normalized.get("average_risk_score", 0.0))
    return normalized


def _upstash_request(command):
    url = os.environ["UPSTASH_REDIS_REST_URL"].rstrip("/")
    payload = json.dumps(command).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {os.environ['UPSTASH_REDIS_REST_TOKEN']}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _load_stats_from_upstash():
    try:
        result = _upstash_request(["GET", STATS_REDIS_KEY])
        raw_value = result.get("result")
        if not raw_value:
            return None
        return _normalize_stats(json.loads(raw_value))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TypeError, ValueError):
        return None


def _save_stats_to_upstash(stats):
    serialized = json.dumps(stats)
    _upstash_request(["SET", STATS_REDIS_KEY, serialized])


def _load_stats_from_file():
    for path in (_writable_stats_file(), BUNDLED_STATS_FILE):
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    return _normalize_stats(json.load(handle))
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                continue
    return None


def _save_stats_to_file(stats):
    try:
        with open(_writable_stats_file(), "w", encoding="utf-8") as handle:
            json.dump(stats, handle)
    except OSError:
        pass


def load_stats():
    global _STATS_CACHE

    if _use_upstash():
        stats = _load_stats_from_upstash()
        if stats is None:
            stats = _load_stats_from_file() or _default_stats()
            _save_stats_to_upstash(stats)
        _STATS_CACHE = stats
        return dict(stats)

    if _STATS_CACHE is not None and not _is_serverless():
        return dict(_STATS_CACHE)

    stats = _load_stats_from_file()
    if stats is None:
        stats = _default_stats()
        save_stats(stats)
        return dict(stats)

    _STATS_CACHE = stats
    return dict(stats)


def save_stats(stats):
    global _STATS_CACHE
    normalized = _normalize_stats(stats)
    _STATS_CACHE = normalized

    if _use_upstash():
        _save_stats_to_upstash(normalized)
        return

    _save_stats_to_file(normalized)


def track_scan(scan_type, score):
    stats = load_stats()
    stats["today_scans"] += 1

    if scan_type == "qr":
        stats["qr_scans"] += 1

    is_threat = score >= 40
    if is_threat:
        stats["threats_detected"] += 1
    else:
        stats["safe_urls"] += 1

    total_prev = stats["today_scans"] - 1
    if total_prev < 0:
        total_prev = 0
    stats["average_risk_score"] = round(
        (stats["average_risk_score"] * total_prev + score) / stats["today_scans"],
        1,
    )

    save_stats(stats)
