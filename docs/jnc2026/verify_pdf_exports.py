"""Structural checks for the generated JNC PDF attachments (standard library only)."""

from pathlib import Path
import re
import sys


EXPECTED = {
    "CyberShield_AI_Dossier_JNC_2026.pdf": 7,
    "CyberShield_AI_Fiche_Technique_JNC_2026.pdf": 3,
}
ROOT = Path(__file__).resolve().parent / "pdf"
failed = False

for filename, expected_pages in EXPECTED.items():
    path = ROOT / filename
    if not path.is_file():
        print(f"FAIL {filename}: missing")
        failed = True
        continue

    data = path.read_bytes()
    page_objects = len(re.findall(rb"/Type\s*/Page(?!s)", data))
    media_boxes = re.findall(rb"/MediaBox\s*\[([^\]]+)\]", data)
    a4_boxes = 0
    for box in media_boxes:
        try:
            left, bottom, right, top = map(float, box.split())
        except ValueError:
            continue
        width, height = abs(right - left), abs(top - bottom)
        if 590 <= width <= 600 and 837 <= height <= 847:
            a4_boxes += 1

    valid = (
        data.startswith(b"%PDF-")
        and data.rstrip().endswith(b"%%EOF")
        and page_objects == expected_pages
        and (not media_boxes or a4_boxes == expected_pages)
    )
    print(
        f"{'PASS' if valid else 'FAIL'} {filename}: {len(data):,} bytes, "
        f"{page_objects}/{expected_pages} page objects, "
        f"{a4_boxes}/{len(media_boxes)} A4 MediaBox entries"
    )
    failed |= not valid

sys.exit(1 if failed else 0)
