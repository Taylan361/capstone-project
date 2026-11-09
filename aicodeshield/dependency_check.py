import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen


MAX_DEPENDENCIES = 100
MAX_ADVISORIES = 30
TIMEOUT_SECONDS = 5
VERSION_PATTERN = re.compile(r"^v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$")
PYTHON_PIN_PATTERN = re.compile(r"^(?:==|===)\s*(\d+(?:\.\d+){1,3}(?:[a-zA-Z0-9.+-]+)?)$")
NUMERIC_VERSION_PATTERN = re.compile(r"^\d+(?:\.\d+){1,3}$")
PACKAGE_NAME_PATTERN = re.compile(r"^(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9][A-Za-z0-9._-]*$")


def _fetch_json(url, payload=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Accept": "application/json", "User-Agent": "AICodeShield-Capstone/0.2"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = Request(url, data=body, headers=headers)
    with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        if urlsplit(response.geturl()).hostname != urlsplit(url).hostname:
            raise URLError("Unexpected registry redirect host")
        return json.loads(response.read())


def _ecosystem_for(dependency):
    manifest = dependency.get("manifest", "").lower()
    if manifest.endswith("package.json") or dependency.get("section"):
        return "npm"
    if manifest.endswith("requirements.txt"):
        return "PyPI"
    return None


def _valid_package_name(name, ecosystem):
    if not isinstance(name, str) or len(name) > 214 or not PACKAGE_NAME_PATTERN.fullmatch(name):
        return False
    if ecosystem == "PyPI" and name.startswith("@"):
        return False
    return True


def _pinned_version(dependency, ecosystem):
    declared = dependency.get("declared_version")
    if not isinstance(declared, str):
        return None
    value = declared.strip()
    if ecosystem == "npm":
        match = VERSION_PATTERN.fullmatch(value)
        return match.group(1) if match else None
    if ecosystem == "PyPI":
        match = PYTHON_PIN_PATTERN.fullmatch(value)
        if match and not value.endswith(".*"):
            return match.group(1)
    return None


def _registry_url(ecosystem, name):
    encoded_name = quote(name, safe="")
    if ecosystem == "npm":
        return f"https://registry.npmjs.org/{encoded_name}"
    return f"https://pypi.org/pypi/{encoded_name}/json"


def _registry_lookup(ecosystem, name):
    url = _registry_url(ecosystem, name)
    try:
        data = _fetch_json(url)
        if ecosystem == "npm":
            latest = data.get("dist-tags", {}).get("latest")
        else:
            latest = data.get("info", {}).get("version")
        return {"registry_status": "found_public", "latest_version": latest}
    except HTTPError as error:
        if error.code == 404:
            error.close()
            return {
                "registry_status": "not_found_public",
                "registry_note": "Not found in this public registry; this may be a private or internal package.",
            }
        status = error.code
        error.close()
        return {"registry_status": "lookup_unavailable", "registry_note": f"Registry returned HTTP {status}."}
    except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        return {"registry_status": "lookup_unavailable", "registry_note": "Public registry lookup failed or timed out."}


def _version_comparison(version, latest):
    if not isinstance(version, str) or not isinstance(latest, str):
        return "not_comparable"
    if not NUMERIC_VERSION_PATTERN.fullmatch(version) or not NUMERIC_VERSION_PATTERN.fullmatch(latest):
        return "not_comparable"
    current_parts = tuple(int(part) for part in version.split("."))
    latest_parts = tuple(int(part) for part in latest.split("."))
    length = max(len(current_parts), len(latest_parts))
    current_parts += (0,) * (length - len(current_parts))
    latest_parts += (0,) * (length - len(latest_parts))
    return "update_available" if latest_parts > current_parts else "current"


def _cvss_label(vulnerability):
    database_severity = vulnerability.get("database_specific", {}).get("severity")
    if isinstance(database_severity, str) and database_severity.upper() in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return database_severity.lower()
    for entry in vulnerability.get("severity", []):
        score = entry.get("score", "")
        if isinstance(score, str) and re.fullmatch(r"\d+(?:\.\d+)?", score):
            numeric_score = float(score)
            if numeric_score >= 9:
                return "critical"
            if numeric_score >= 7:
                return "high"
            if numeric_score >= 4:
                return "medium"
            if numeric_score > 0:
                return "low"
    return "unknown"


def _advisory_details(identifier):
    try:
        vulnerability = _fetch_json(f"https://api.osv.dev/v1/vulns/{quote(identifier, safe='')}")
        fixed_versions = []
        for affected in vulnerability.get("affected", []):
            for version_range in affected.get("ranges", []):
                for event in version_range.get("events", []):
                    fixed = event.get("fixed")
                    if isinstance(fixed, str) and fixed not in fixed_versions:
                        fixed_versions.append(fixed)
        references = [
            {"type": reference.get("type", "WEB"), "url": reference["url"]}
            for reference in vulnerability.get("references", [])
            if isinstance(reference, dict)
            and isinstance(reference.get("url"), str)
            and reference["url"].startswith("https://")
        ][:5]
        return {
            "id": vulnerability.get("id", identifier),
            "aliases": vulnerability.get("aliases", [])[:8],
            "summary": (vulnerability.get("summary") or "Known vulnerability advisory")[:240],
            "severity": _cvss_label(vulnerability),
            "modified": vulnerability.get("modified"),
            "fixed_versions": fixed_versions[:8],
            "references": references,
        }
    except HTTPError as error:
        error.close()
        return {"id": identifier, "aliases": [], "summary": "Known advisory; details could not be retrieved.", "severity": "unknown"}
    except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        return {"id": identifier, "aliases": [], "summary": "Known advisory; details could not be retrieved.", "severity": "unknown"}


def check_dependencies(dependencies):
    enriched = [dict(dependency) for dependency in dependencies]
    package_keys = []
    for dependency in enriched:
        ecosystem = _ecosystem_for(dependency)
        name = dependency.get("name")
        if ecosystem is None or not _valid_package_name(name, ecosystem):
            dependency.update({"ecosystem": ecosystem or "unsupported", "registry_status": "not_checked", "advisory_status": "not_checked"})
            continue
        version = _pinned_version(dependency, ecosystem)
        dependency["ecosystem"] = ecosystem
        dependency["pinned_version"] = version
        dependency["advisories"] = []
        dependency["registry_status"] = "pending"
        dependency["advisory_status"] = "version_unpinned" if version is None else "pending"
        package_key = (ecosystem, name.casefold())
        if package_key not in package_keys:
            package_keys.append(package_key)

    checked_keys = package_keys[:MAX_DEPENDENCIES]
    registry_data = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        future_map = {
            pool.submit(_registry_lookup, ecosystem, next(dep["name"] for dep in enriched if dep.get("ecosystem") == ecosystem and dep.get("name", "").casefold() == normalized_name)): (ecosystem, normalized_name)
            for ecosystem, normalized_name in checked_keys
        }
        for future in as_completed(future_map):
            registry_data[future_map[future]] = future.result()

    queries = []
    query_dependencies = []
    for dependency in enriched:
        ecosystem = dependency.get("ecosystem")
        name = dependency.get("name")
        if ecosystem not in {"npm", "PyPI"} or not isinstance(name, str):
            continue
        package_key = (ecosystem, name.casefold())
        if package_key not in checked_keys:
            dependency.update({"registry_status": "not_checked_limit", "advisory_status": "not_checked_limit"})
            continue
        dependency.update(registry_data.get(package_key, {"registry_status": "lookup_unavailable"}))
        latest = dependency.get("latest_version")
        pinned = dependency.get("pinned_version")
        dependency["version_status"] = "unpinned" if pinned is None else _version_comparison(pinned, latest)
        if pinned is not None:
            queries.append({"package": {"name": name, "ecosystem": ecosystem}, "version": pinned})
            query_dependencies.append(dependency)

    if not queries:
        query_status = "no_exact_versions_to_check"
    else:
        try:
            batch = _fetch_json("https://api.osv.dev/v1/querybatch", {"queries": queries})
            results = batch.get("results")
            if not isinstance(results, list) or len(results) != len(query_dependencies):
                raise ValueError("OSV batch response did not match query count")
            raw_ids = []
            for dependency, result in zip(query_dependencies, results):
                advisories = result.get("vulns", []) if isinstance(result, dict) else []
                ids = [item.get("id") for item in advisories if isinstance(item, dict) and isinstance(item.get("id"), str)]
                dependency["advisory_ids"] = ids
                dependency["advisory_count"] = len(ids)
                dependency["advisory_status"] = "checked_with_findings" if ids else "checked_no_known_advisories"
                raw_ids.extend(ids)
            identifiers = list(dict.fromkeys(raw_ids))
            detail_ids = identifiers[:MAX_ADVISORIES]
            details = {}
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = {pool.submit(_advisory_details, identifier): identifier for identifier in detail_ids}
                for future in as_completed(futures):
                    details[futures[future]] = future.result()
            for dependency in query_dependencies:
                dependency["advisories"] = [details[identifier] for identifier in dependency.get("advisory_ids", []) if identifier in details]
                if any(identifier not in details for identifier in dependency.get("advisory_ids", [])):
                    dependency["advisory_details_truncated"] = True
            query_status = "completed"
        except HTTPError as error:
            error.close()
            for dependency in query_dependencies:
                dependency["advisory_status"] = "lookup_unavailable"
            query_status = "unavailable"
        except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
            for dependency in query_dependencies:
                dependency["advisory_status"] = "lookup_unavailable"
            query_status = "unavailable"

    for dependency in enriched:
        if dependency.get("registry_status") == "pending":
            dependency["registry_status"] = "lookup_unavailable"
        if dependency.get("advisory_status") == "pending":
            dependency["advisory_status"] = "lookup_unavailable"
        if dependency.get("ecosystem") in {"npm", "PyPI"} and dependency.get("advisory_status") == "version_unpinned":
            dependency["advisory_note"] = "A lockfile or exact version is needed for a precise vulnerability query."

    return enriched, {
        "status": query_status,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": ["OSV.dev", "npm public registry", "PyPI"],
        "packages_checked": len(checked_keys),
        "package_limit": MAX_DEPENDENCIES,
        "advisory_detail_limit": MAX_ADVISORIES,
    }
