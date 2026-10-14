#!/usr/bin/env python3
"""Hash preserved root-owned run artifacts without changing any source run."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAMES = ('critical.raw', 'general.raw', 'quarantine.raw', 'evidence.meta',
         'evidence.meta.commit', 'manifest.json', 'config.json', 'health.json',
         'index-health.json', 'index.sqlite')


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    result = {}
    for summary in sorted((HERE / 'runs').glob('*.json')):
        if summary.name.endswith('-error.json'):
            continue
        original = json.loads(summary.read_text())
        run = Path(original['run_dir'])
        result[original['label']] = {
            'original_summary_sha256': sha256(summary),
            'run_id': original['run_id'], 'run_dir': str(run),
            'files': {name: dict(bytes=(run / name).stat().st_size,
                                 sha256=sha256(run / name))
                      for name in NAMES if (run / name).is_file()}}
    with (HERE / 'artifact-hashes-eb9c888.json').open('w', encoding='utf-8') as file:
        json.dump(dict(scope='READ_ONLY_HASH_OF_PRESERVED_RUN_ARTIFACTS', runs=result), file,
                  indent=2, sort_keys=True)
        file.write('\n')


if __name__ == '__main__':
    main()
