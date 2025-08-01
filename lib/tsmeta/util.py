import re

# Maps (detail, decoded_status) with vuln_status in vigiles
VIGILES_STATUS_MAP = {
    ("patched", "patched"): "resolved_with_pedigree",
    ("backported-patch", "patched"): "resolved_with_pedigree",
    ("cpe-stable-backport", "patched"): "resolved",
    ("fixed-version", "patched"): "resolved",
    ("fix-file-included", "patched"): "resolved_with_pedigree",
    ("version-not-in-range", "patched"): "resolved",
    ("unpatched", "unpatched"): "exploitable",
    ("vulnerable-investigating", "unpatched"): "in_triage",
    ("version-in-range", "unpatched"): "exploitable",
    ("ignored","ignored"): "not_affected",
    ("cpe-incorrect","ignored"): "not_affected",
    ("disputed","ignored"): "not_affected",
    ("not-applicable-config","ignored"): "not_affected",
    ("not-applicable-platform","ignored"): "not_affected",
    ("upstream-wontfix","ignored"): "not_affected",
    ("unknown", "unknown"): "exploitable",
}


VIGILES_JUSTIFICATION_MAP = {
    "not-applicable-config": "code_not_present",
    "not-applicable-platform": "code_not_present"
}

VALID_VULN_REGEX = [
    r"^CVE-\d{4}-\d{4,}$",                         # NVD
    r"^[a-zA-Z0-9]+-\d{4}-\d{1,}$",                # OSV
    r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", # Github Advisory
]


def get_vuln_status(cve_status):
    detail = cve_status.get("detail")
    decoded_status = cve_status.get("decoded_status", "").lower()
    return VIGILES_STATUS_MAP.get((detail, decoded_status), "exploitable")

def get_vuln_justification(cve_status):
    detail = cve_status.get("detail")
    return VIGILES_JUSTIFICATION_MAP.get(detail, "")

def get_vuln_description(cve_status):
    detail = cve_status.get("detail")
    description = cve_status.get("description")
    return f"{detail}: {description}"

def validate_vuln_id(vuln_id):
    for pattern in VALID_VULN_REGEX:
        match = re.match(pattern, vuln_id)
        if match:
            return True
    return False