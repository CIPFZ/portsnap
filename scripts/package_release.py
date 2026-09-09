"""Create a portable release archive and SHA-256 checksum (stdlib only)."""
import argparse
import hashlib
from pathlib import Path
import re
import tarfile
import zipfile


def package(binary: Path, target: str, version: str, output: Path, root: Path) -> Path:
    if not re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
                        r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
                        r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
                        r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", version):
        raise ValueError("version must be a v-prefixed semantic version")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", target):
        raise ValueError("invalid target triple")
    files = [(binary, "portsnap.exe" if "windows" in target else "portsnap"),
             (root / "LICENSE", "LICENSE"), (root / "README.md", "README.md")]
    for source, _ in files:
        if not source.is_file():
            raise FileNotFoundError(source)
    output.mkdir(parents=True, exist_ok=True)
    stem = f"portsnap-{version}-{target}"
    archive = output / (stem + (".zip" if "windows" in target else ".tar.gz"))
    if "windows" in target:
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            for source, name in files:
                bundle.write(source, name)
    else:
        with tarfile.open(archive, "w:gz") as bundle:
            for source, name in files:
                info = bundle.gettarinfo(str(source), arcname=name)
                info.mode = 0o755 if name == "portsnap" else 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                with source.open("rb") as contents:
                    bundle.addfile(info, contents)
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_name(archive.name + ".sha256").write_text(
        f"{checksum}  {archive.name}\n", encoding="ascii")
    return archive


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(package(args.binary, args.target, args.version, args.output,
                  Path(__file__).resolve().parents[1]))


if __name__ == "__main__":
    main()
