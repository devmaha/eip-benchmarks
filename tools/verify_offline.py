#!/usr/bin/env python3
"""Fail-closed offline verification of historical EIP benchmark evidence.

No model or network calls. Accepts two evidence ZIP assets or extracted evidence
folders. Checks per-file SHA-256 against the published immutable evidence manifest,
then recomputes the full original scoring summaries with the original strict scorers.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / 'docs/EVIDENCE_SHA256_MANIFEST.json'


def digest(file_obj) -> str:
    h = hashlib.sha256()
    for chunk in iter(lambda: file_obj.read(1024 * 1024), b''):
        h.update(chunk)
    return h.hexdigest()


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'cannot load scorer {path}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unpack_checked(archive: Path, suite: str, target: Path, manifest: dict[str, str]):
    prefix = f'benchmarks/{suite}/evidence/'
    expected = {p: sha for p, sha in manifest.items() if p.startswith(prefix)}
    observed: set[str] = set()
    total_bytes = 0
    with zipfile.ZipFile(archive) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            path = PurePosixPath(info.filename)
            if str(path) != info.filename or path.is_absolute() or '..' in path.parts:
                raise ValueError(f'unsafe ZIP entry: {info.filename}')
            if not info.filename.startswith(prefix):
                raise ValueError(f'unexpected entry in {suite} evidence archive: {info.filename}')
            if info.filename not in expected or info.filename in observed:
                raise ValueError(f'unexpected/duplicate evidence entry: {info.filename}')
            # Reject ZIP symlinks and oversized unexpected entries.
            if ((info.external_attr >> 16) & 0o170000) == 0o120000:
                raise ValueError(f'symlink not allowed: {info.filename}')
            total_bytes += info.file_size
            if total_bytes > 120 * 1024 * 1024:
                raise ValueError('unexpectedly large evidence archive')
            dest = target.joinpath(*path.parts)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, dest.open('wb') as out:
                h = hashlib.sha256()
                for chunk in iter(lambda: src.read(1024 * 1024), b''):
                    out.write(chunk)
                    h.update(chunk)
            if h.hexdigest() != expected[info.filename]:
                raise ValueError(f'SHA-256 mismatch in {info.filename}')
            observed.add(info.filename)
    if observed != set(expected):
        missing = sorted(set(expected) - observed)
        raise ValueError(f'{suite}: expected {len(expected)} files, found {len(observed)}; first missing: {missing[:3]}')
    print(f'{suite}: verified SHA-256 for {len(observed)} raw records')


def verify_scores(name: str, scorer_path: str) -> None:
    path = ROOT / scorer_path
    module = load(path, f'{name}_strict')
    fresh = module.compute(write=False)
    stored = json.loads((path.parent.parent / 'audit' / 'aggregate_summary.json').read_text())
    if json.loads(json.dumps(fresh)) != stored:
        raise ValueError(f'{name}: recomputed summary differs from stored audit')
    print(f'{name}: strict score matches released audit')


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--agentdyn-zip', type=Path, help='AgentDyn raw evidence ZIP asset')
    ap.add_argument('--agentdojo-zip', type=Path, help='AgentDojo raw evidence ZIP asset')
    ap.add_argument('--extracted-root', type=Path, help='Existing directory containing benchmarks/*/evidence')
    args = ap.parse_args()
    if bool(args.agentdyn_zip) != bool(args.agentdojo_zip):
        ap.error('supply both ZIP files, not just one')
    if args.extracted_root and args.agentdyn_zip:
        ap.error('use either two ZIPs or --extracted-root')
    try:
        data = json.loads(MANIFEST.read_text())
        file_hashes = data['per_file_sha256']
        with tempfile.TemporaryDirectory(prefix='eip_verified_') as d:
            if args.agentdyn_zip:
                data_root = Path(d)
                for suite, archive in [('agentdyn', args.agentdyn_zip), ('agentdojo', args.agentdojo_zip)]:
                    unpack_checked(archive, suite, data_root, file_hashes)
            else:
                data_root = args.extracted_root or ROOT
                for suite in ('agentdyn', 'agentdojo'):
                    # Verify content in normal extracted layout, too.
                    prefix = f'benchmarks/{suite}/evidence/'
                    expected = {p: sha for p, sha in file_hashes.items() if p.startswith(prefix)}
                    base = data_root / 'benchmarks' / suite / 'evidence'
                    found = {str(p.relative_to(data_root)) for p in base.rglob('*.json')} if base.is_dir() else set()
                    if found != set(expected):
                        raise ValueError(f'{suite}: evidence missing/extra (got {len(found)}; expected {len(expected)}). Download both release ZIPs and pass --agentdyn-zip / --agentdojo-zip.')
                    for rel, sha in expected.items():
                        with (data_root / rel).open('rb') as fh:
                            if digest(fh) != sha:
                                raise ValueError(f'SHA-256 mismatch: {rel}')
                    print(f'{suite}: verified SHA-256 for {len(found)} raw records')
            previous = os.environ.get('EIP_EVIDENCE_ROOT')
            os.environ['EIP_EVIDENCE_ROOT'] = str(data_root)
            try:
                verify_scores('AgentDyn', 'benchmarks/agentdyn/tools/aggregate_strict.py')
                verify_scores('AgentDojo', 'benchmarks/agentdojo/tools/aggregate_strict.py')
            finally:
                if previous is None:
                    os.environ.pop('EIP_EVIDENCE_ROOT', None)
                else:
                    os.environ['EIP_EVIDENCE_ROOT'] = previous
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        print(f'OFFLINE VERIFICATION FAILED: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
