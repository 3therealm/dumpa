"""Permission -> data-access capability mapping (the declared-capability report).

A declared `<uses-permission>` is a definitive signal that the app *can* touch a
data class, so these findings are high-confidence and state ``present``. Whether the
capability is actually exercised in code is a separate signal — the privacy API
scanner (privacy.toml, state ``referenced``) covers that.
"""

from __future__ import annotations

from dumpa.core.report import Confidence, Evidence, Finding, FindingState

const_capability_kind = "capability"

# Android permission -> (capability category, human label). Categories mirror the
# Phase 6 data-access list (advertising id, location, contacts, ... network state).
PERMISSION_CAPABILITIES: dict[str, tuple[str, str]] = {
    "com.google.android.gms.permission.AD_ID": ("advertising id", "Advertising ID (AD_ID)"),
    "android.permission.ACCESS_FINE_LOCATION": ("location", "Precise location"),
    "android.permission.ACCESS_COARSE_LOCATION": ("location", "Approximate location"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("location", "Background location"),
    "android.permission.READ_CONTACTS": ("contacts", "Read contacts"),
    "android.permission.WRITE_CONTACTS": ("contacts", "Write contacts"),
    "android.permission.GET_ACCOUNTS": ("accounts", "Device accounts"),
    "android.permission.RECORD_AUDIO": ("microphone", "Microphone"),
    "android.permission.CAMERA": ("camera", "Camera"),
    "android.permission.READ_PHONE_STATE": ("device identifiers", "Phone state / device identifiers"),
    "android.permission.READ_EXTERNAL_STORAGE": ("external storage", "Read external storage"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("external storage", "Write external storage"),
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("external storage", "Manage all files"),
    "android.permission.BODY_SENSORS": ("sensors", "Body sensors"),
    "android.permission.ACTIVITY_RECOGNITION": ("sensors", "Activity recognition"),
    "android.permission.QUERY_ALL_PACKAGES": ("installed packages", "Query all installed packages"),
    "android.permission.BLUETOOTH": ("bluetooth", "Bluetooth (legacy)"),
    "android.permission.BLUETOOTH_CONNECT": ("bluetooth", "Bluetooth connect"),
    "android.permission.BLUETOOTH_SCAN": ("bluetooth", "Bluetooth scan"),
    "android.permission.ACCESS_WIFI_STATE": ("network", "Wi-Fi state"),
    "android.permission.CHANGE_WIFI_STATE": ("network", "Change Wi-Fi state"),
    "android.permission.ACCESS_NETWORK_STATE": ("network", "Network state"),
}


def permission_findings(permissions: list[str]) -> list[Finding]:
    """Map an app's declared permissions to data-access capability findings."""
    findings: list[Finding] = []
    for permission in permissions:
        mapped = PERMISSION_CAPABILITIES.get(permission)
        if mapped is None:
            continue
        category, label = mapped
        findings.append(Finding(
            kind=const_capability_kind,
            subject=label,
            confidence=Confidence.HIGH,
            state=FindingState.PRESENT,
            attributes={"category": category, "permission": permission},
            evidence=[Evidence(description=f"declared <uses-permission> {permission}", tool="manifest")],
        ))
    return findings
