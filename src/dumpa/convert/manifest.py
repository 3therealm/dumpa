"""Finalize the merged main APK: strip signature leftovers, dummies, split attrs."""

from __future__ import annotations

import re
from pathlib import Path

from dumpa.core.fs import delete_file_if_exists


def delete_signature_related_files(path_to_main_apk: Path) -> None:
    """Remove the bundled META-INF entries left behind by apktool.

    Splits may carry CERT.* or other arbitrarily-named signature blocks; apksigner
    refuses to sign if any leftover *.RSA/*.SF/*.DSA/*.EC/*.MF remain.
    """
    meta_inf = path_to_main_apk / 'original' / 'META-INF'
    if not meta_inf.is_dir():
        return
    for ext in ('RSA', 'SF', 'DSA', 'EC', 'MF'):
        for f in meta_inf.glob(f'*.{ext}'):
            delete_file_if_exists(f)


_split_attr_pattern = re.compile(
    r'\s+android:(?:isSplitRequired|requiredSplitTypes|splitTypes)="[^"]*"'
)


# Matches a single XML element on its own line whose tag (or attribute) contains
# APKTOOL_DUMMY_*. Covers: <attr .../>, <public .../>, <item ...>val</item>.
_apktool_dummy_line = re.compile(
    r'^[ \t]*<[^>]*\bAPKTOOL_DUMMY_[^>]*>(?:[^<\n]*</\w+>)?[ \t]*\n',
    re.MULTILINE,
)


def strip_apktool_dummies(main_apk_dir: Path) -> int:
    """Remove APKTOOL_DUMMY_* placeholder entries from merged values XML.

    Apktool emits APKTOOL_DUMMY_<hex> when decoding a config split alone — those
    attr IDs only resolve in the base apk's public table. Once merged into base,
    aapt2 link rejects the dummies at rebuild. Stripping is safe: real attrs
    defined in base remain; only unresolvable per-config overrides are dropped.

    Returns the number of XML files modified.
    """
    res_dir = main_apk_dir / 'res'
    if not res_dir.is_dir():
        return 0
    modified = 0
    for top in res_dir.iterdir():
        if not top.is_dir() or not top.name.startswith('values'):
            continue
        for xml_path in top.rglob('*.xml'):
            text = xml_path.read_text(encoding='UTF-8')
            if 'APKTOOL_DUMMY_' not in text:
                continue
            new_text = _apktool_dummy_line.sub('', text)
            if new_text != text:
                xml_path.write_text(new_text, encoding='UTF-8')
                modified += 1
    return modified


def update_main_manifest_file(path_main_apk: Path) -> None:
    """Strip split-bundle attributes from the merged AndroidManifest.xml."""
    path_manifest = path_main_apk / 'AndroidManifest.xml'

    literal_replacements = {
        '<meta-data android:name="com.google.firebase.messaging.default_notification_icon" android:resource="@null"/>': '',
        'android:value="STAMP_TYPE_DISTRIBUTION_APK"': 'android:value="STAMP_TYPE_STANDALONE_APK"',
        '<meta-data android:name="com.android.vending.splits.required" android:value="true"/>': '',
        '<meta-data android:name="com.android.vending.splits" android:resource="@xml/splits0"/>': '',
    }

    with path_manifest.open(encoding='UTF-8') as f:
        data = f.read()
    # Strip split-related attrs regardless of value; eat leading whitespace to avoid double-spaces.
    data = _split_attr_pattern.sub('', data)
    for from_str, to_str in literal_replacements.items():
        data = data.replace(from_str, to_str)
    # Atomic swap so a crash mid-write cannot corrupt the manifest.
    tmp_path = path_manifest.with_suffix('.xml.tmp')
    with tmp_path.open('w', encoding='UTF-8') as f:
        f.write(data)
    tmp_path.replace(path_manifest)
