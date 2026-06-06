"""Parsing and merging of apktool.yml `doNotCompress:` blocks."""

from __future__ import annotations

from pathlib import Path

from dumpa.convert.models import ApktoolConfig


def get_do_not_compress_lines(config_file_lines: list[str]) -> tuple[list[str], int, int]:
    """Locate the `doNotCompress:` block in apktool.yml lines; return (lines, start_idx, end_idx).

    `start_idx` is the index of the first list item line (after the `doNotCompress:` header).
    `end_idx` is the index one past the last list item line (suitable for a Python slice).
    Returns (-1, -1) for both when the block is absent.
    """
    index_start = -1
    index_end = -1
    result: list[str] = []
    start_block_literal = 'doNotCompress:'
    prefix_target_line = '- '
    opened = False
    for index, line in enumerate(config_file_lines):
        if not opened and line.startswith(start_block_literal):
            opened = True
            index_start = index + 1
        elif opened and line.startswith(prefix_target_line):
            result.append(line)
        elif opened and not line.startswith(prefix_target_line):
            index_end = index
            break
    if opened and index_end == -1:
        # Block ran to EOF without a trailing non-`-` line.
        index_end = len(config_file_lines)
    result.sort()
    return result, index_start, index_end


def parse_apktool_config(config_file_path: Path) -> ApktoolConfig:
    """Parse apktool.yml into an ApktoolConfig dataclass."""
    with config_file_path.open(encoding='UTF-8') as f:
        lines = f.readlines()
    do_not_compress_lines, idx_start, idx_end = get_do_not_compress_lines(lines)
    return ApktoolConfig(lines, do_not_compress_lines, idx_start, idx_end)


def insert_new_lines_do_not_compress(config_file_path: Path, lines_to_insert: list[str]) -> None:
    """Merge lines into the `doNotCompress:` block (sorted, dedup) and rewrite the file.

    If the file has no `doNotCompress:` block, append a new one at EOF.
    """
    cfg = parse_apktool_config(config_file_path)
    merged = sorted(set(cfg.lines_do_not_compress) | set(lines_to_insert))

    updated = list(cfg.lines_all)
    if cfg.lines_do_not_compress_index_start == -1:
        # No existing block: append a fresh one. Ensure prior content ends with newline.
        if updated and not updated[-1].endswith('\n'):
            updated[-1] = updated[-1] + '\n'
        updated.append('doNotCompress:\n')
        updated.extend(merged)
    else:
        updated[cfg.lines_do_not_compress_index_start:cfg.lines_do_not_compress_index_end] = merged
    with config_file_path.open('w', encoding='UTF-8') as f:
        f.writelines(updated)
