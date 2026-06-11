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


const_ad_id_permission = "com.google.android.gms.permission.AD_ID"
const_ad_id_attribution_kind = "ad-id-attribution"

# Tracker subjects (as in rules/trackers.toml) for SDKs that declare AD_ID in their own
# manifest, so the permission is merged into the final APK at build time even if the app
# never declares it. Static merge inference: if the SDK and the AD_ID permission both
# appear, the SDK is a likely source. Value = why (a short note kept for the curated map).
AD_ID_SOURCES: dict[str, str] = {
    "Google AdMob / Mobile Ads": "Google Mobile Ads SDK declares AD_ID",
    "Firebase Analytics": "Firebase/GMS measurement declares AD_ID",
    "Google Analytics": "GMS analytics declares AD_ID",
    "Meta Audience Network": "Meta Audience Network declares AD_ID",
    "AppLovin MAX": "AppLovin declares AD_ID",
    "Unity Ads": "Unity Ads declares AD_ID",
    "Unity LevelPlay / ironSource": "ironSource/LevelPlay declares AD_ID",
    "Vungle / Liftoff": "Vungle/Liftoff declares AD_ID",
    "AppsFlyer": "AppsFlyer attribution reads AD_ID",
    "Adjust": "Adjust attribution reads AD_ID",
}


def attribute_ad_id(findings: list[Finding]) -> list[Finding]:
    """Attribute a merged AD_ID permission to the SDK(s) that likely introduced it.

    Manifest-merge inference (Phase 6): the `AD_ID` permission is often added not by the app
    but by an ad/attribution SDK whose own manifest declares it. When an AD_ID capability
    finding is present, name every detected tracker in `AD_ID_SOURCES` as a likely source.
    Emits at most one `ad-id-attribution` finding (state present, medium confidence — a static
    merge inference, not proof the app authored the permission). Empty when AD_ID is absent.
    """
    has_ad_id = any(f.kind == const_capability_kind
                    and f.attributes.get("permission") == const_ad_id_permission
                    for f in findings)
    if not has_ad_id:
        return []
    sources = sorted({f.subject for f in findings
                      if f.kind == "tracker" and f.subject in AD_ID_SOURCES})
    source_text = ", ".join(sources) if sources else "unknown (no known AD_ID-injecting SDK detected)"
    evidence = [Evidence(
        description=f"{const_ad_id_permission} present; likely contributed via manifest merge by: {source_text}",
        tool="privacy",
    )]
    return [Finding(
        kind=const_ad_id_attribution_kind,
        subject="Advertising ID (AD_ID) source",
        confidence=Confidence.MEDIUM,
        state=FindingState.PRESENT,
        attributes={"source": source_text},
        evidence=evidence,
    )]


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
