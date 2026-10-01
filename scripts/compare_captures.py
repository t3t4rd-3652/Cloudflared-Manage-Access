"""Compare deux séries de captures d'écran et signale les écrans qui ont changé.

    uv run python scripts/compare_captures.py <avant> <après> [--diff <dossier>] [--threshold 0.5]

Pour chaque image présente des deux côtés, compte la part de pixels qui diffèrent nettement (écart > 24 sur un
canal). Au-delà du seuil (en %), une image de différence est écrite : pixels changés en magenta sur l'image
d'après, assombrie. Le tableau est affiché et ajouté au résumé du job GitHub Actions. Le script est informatif :
il réussit toujours, une modification d'interface pouvant être voulue.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from PySide6.QtGui import QColor, QImage

TOLERANCE = 24


def compare(before: Path, after: Path, diff_path: Path | None) -> float:
    old = QImage(str(before)).convertToFormat(QImage.Format.Format_RGB32)
    new = QImage(str(after)).convertToFormat(QImage.Format.Format_RGB32)
    if old.size() != new.size():
        return 100.0
    width, height = new.width(), new.height()
    stride = new.bytesPerLine()
    old_bytes, new_bytes = bytes(old.constBits()), bytes(new.constBits())  # type: ignore[call-overload]
    changed = 0
    diff = QImage(new) if diff_path is not None else None
    if diff is not None:
        # Fond assombri : seuls les pixels changés ressortent, en magenta.
        for y in range(height):
            for x in range(width):
                diff.setPixel(x, y, QColor(new.pixel(x, y)).darker(250).rgb())
    for y in range(height):
        row = slice(y * stride, y * stride + width * 4)
        if old_bytes[row] == new_bytes[row]:
            continue  # la plupart des lignes sont identiques : comparaison rapide en mémoire
        for x in range(width):
            offset = y * stride + x * 4
            a, b = old_bytes[offset : offset + 3], new_bytes[offset : offset + 3]
            if a != b and max(abs(i - j) for i, j in zip(a, b, strict=True)) > TOLERANCE:
                changed += 1
                if diff is not None:
                    diff.setPixel(x, y, QColor(255, 0, 255).rgb())
    ratio = 100.0 * changed / (width * height)
    if diff is not None and diff_path is not None:
        diff_path.parent.mkdir(parents=True, exist_ok=True)
        diff.save(str(diff_path))
    return ratio


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--diff", type=Path)
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args()
    rows = []
    for image in sorted(args.after.rglob("*.png")):
        relative = image.relative_to(args.after)
        previous = args.before / relative
        if not previous.exists():
            rows.append((str(relative), "nouvelle"))
            continue
        ratio = compare(previous, image, None)
        if ratio > args.threshold and args.diff is not None:
            compare(previous, image, args.diff / relative)
        rows.append((str(relative), f"{ratio:.2f} %" + (" (à vérifier)" if ratio > args.threshold else "")))
    lines = ["| Capture | Pixels changés |", "| --- | --- |", *(f"| `{n}` | {v} |" for n, v in rows)]
    text = "\n".join(lines)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as handle:
            handle.write("### Captures comparées au dernier main\n\n" + text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
