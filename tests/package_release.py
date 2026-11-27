"""Create the two hackathon archives from an explicit allowlist."""

import argparse
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
TOP_LEVEL = (
    ".gitignore", ".gitattributes", "README.md", "DEMO_GUIDE.md",
    "INSTALL.md", "RELEASE_REPORT.md", "COLLABORATIVE_MODEL_REPORT.md",
    "PHISHING_MODEL_REPORT.md", "FINAL_AUDIT.md", "REGRESSION_REPORT.md", "V2_REPORT.md",
    "requirements.txt", "requirements-test.txt", "start_backend.sh", "start_backend.bat",
    "privacy_detector.py", "residential_addresses.py", "url_features.py",
    "models/email_phishing_model.joblib", "models/url_context_candidate.joblib",
    "extension/manifest.json", "extension/package.json", "extension/package-lock.json",
    "extension/popup.html", "extension/vite.config.js", "extension/finish-build.mjs",
    "extension/README.md",
)
SOURCE_DIRS = (
    "backend", "extension/public", "extension/src", "tests", "training", "docs", "Sentinel AI UI logos",
)
EXCLUDED_SUFFIXES = {
    ".db", ".sqlite", ".sqlite3", ".pem", ".key", ".p12", ".pfx", ".log", ".pyc", ".crx",
    ".csv", ".parquet", ".jsonl", ".onnx", ".pt", ".safetensors", ".joblib",
}
REQUIRED_BUNDLE = (
    "manifest.json", "background.js", "content.js", "gmailOverlay.css", "popup.html",
    "models/screening.json", "models/public_suffix_list.dat", "logos/purple_minimal_48.png",
)


def checked_tree(directory):
    for file in sorted(directory.rglob("*")):
        relative = file.relative_to(directory)
        if any(part.startswith(".") or part == "__pycache__" for part in relative.parts):
            continue
        if file.is_symlink():
            raise ValueError(f"Release input contains a symlink: {relative}")
        if file.is_file() and not any(s in EXCLUDED_SUFFIXES for s in file.suffixes) and not any(
            s.startswith((".db-", ".sqlite-", ".sqlite3-")) for s in file.suffixes
        ):
            if file.name in {"credentials.json", "token.json"} or file.name.startswith("client_secret"):
                raise ValueError(f"Release input contains a credential file: {relative}")
            yield file


def write_zip(path, base, paths, prefix):
    with ZipFile(path, "w", compression=ZIP_DEFLATED, compresslevel=6) as archive:
        for file in paths:
            if not file.is_file() or file.is_symlink():
                raise ValueError(f"Missing or invalid release input: {file}")
            archive.write(file, str(Path(prefix) / file.relative_to(base)))
    with ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise ValueError(f"Corrupt ZIP member in {path}")


def package(bundle, output):
    for name in REQUIRED_BUNDLE:
        if not (bundle / name).is_file():
            raise ValueError(f"The extension build is missing {name}")
    for name in ("screening.json", "public_suffix_list.dat"):
        if (bundle / "models" / name).read_bytes() != (ROOT / "extension/public/models" / name).read_bytes():
            raise ValueError(f"Stale extension runtime asset: {name}")
    source_manifest = json.loads((ROOT / "extension/manifest.json").read_bytes())
    built_manifest = json.loads((bundle / "manifest.json").read_bytes())
    if built_manifest != source_manifest or "oauth2" in built_manifest:
        raise ValueError("The public release requires a clean build without a configured OAuth client.")

    output.mkdir(parents=True, exist_ok=False)
    source_files = [ROOT / name for name in TOP_LEVEL]
    source_files.extend(file for name in SOURCE_DIRS for file in checked_tree(ROOT / name))
    write_zip(output / "SentinelAI-Source.zip", ROOT, sorted(source_files), "SentinelAI")
    write_zip(output / "SentinelAI-Extension.zip", bundle, checked_tree(bundle), "SentinelAI-Extension")
    for archive in sorted(output.glob("*.zip")):
        print(f"{archive} ({archive.stat().st_size:,} bytes)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="A new output directory")
    parser.add_argument("--bundle", type=Path, default=ROOT / "extension/dist")
    args = parser.parse_args()
    package(args.bundle.resolve(), args.output.resolve())
