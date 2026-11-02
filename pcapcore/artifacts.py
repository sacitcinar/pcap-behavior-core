"""Staged CLI artifacts: preserve previous results on handled failures.

Each completed file is installed with os.replace().  The collection is *not*
fully crash-atomic (a process kill or power loss during promotion can interrupt
multiple-file replacement); for ordinary exceptions we roll back all targets.
"""
from __future__ import annotations
from pathlib import Path
import os
import tempfile


class ArtifactTransaction:
    def __init__(self, targets: list[Path], *, overwrite: bool = False):
        self.targets = [Path(x) for x in targets]
        self.overwrite = overwrite
        self.stages: dict[Path, Path] = {}
        self.backups: dict[Path, Path] = {}

    @staticmethod
    def _reserve_near(target: Path, marker: str) -> Path:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix='.pcapcore-', suffix=f'.{marker}.tmp', dir=target.parent)
        os.close(fd)
        Path(name).unlink()
        return Path(name)

    def __enter__(self):
        if not self.overwrite:
            present = [p for p in self.targets if p.exists() or p.is_symlink()]
            if present:
                raise FileExistsError(f'Output/index/HTML exists: {present[0]}; use --overwrite')
        try:
            for target in self.targets:
                self.stages[target] = self._reserve_near(target, target.suffix.strip('.') or 'data')
        except BaseException:
            for stage in self.stages.values():
                stage.unlink(missing_ok=True)
            raise
        return self

    def staged(self, target: Path) -> Path:
        return self.stages[Path(target)]

    def commit(self) -> None:
        if not all(stage.is_file() for stage in self.stages.values()):
            raise OSError('All staged artifacts must exist before publication')
        if not self.overwrite and any(p.exists() or p.is_symlink() for p in self.targets):
            raise FileExistsError('A target was created during analysis; refusing to overwrite')
        installed = []
        try:
            if self.overwrite:
                for target in self.targets:
                    if target.exists() or target.is_symlink():
                        backup = self._reserve_near(target, 'backup')
                        os.replace(target, backup)
                        self.backups[target] = backup
            for target in self.targets:
                os.replace(self.stages[target], target)
                installed.append(target)
        except BaseException:
            for target in installed:
                target.unlink(missing_ok=True)
            for target, backup in reversed(list(self.backups.items())):
                os.replace(backup, target)
            self.backups.clear()
            raise
        else:
            for backup in self.backups.values():
                backup.unlink(missing_ok=True)
            self.backups.clear()

    def __exit__(self, *_):
        for stage in self.stages.values():
            stage.unlink(missing_ok=True)
            for suffix in ('-journal', '-wal', '-shm'):
                Path(str(stage) + suffix).unlink(missing_ok=True)
        # If backup restoration itself failed, preserve the backup file for
        # manual recovery; never delete a user's previous successful report.


def normalize_index_references(value, staged_index: Path, final_index: Path):
    """Replace only generated index-location fields, not packet-derived text."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key == 'full_provenance_index' and item == str(staged_index):
                value[key] = str(final_index)
            else:
                normalize_index_references(item, staged_index, final_index)
    elif isinstance(value, list):
        for item in value:
            normalize_index_references(item, staged_index, final_index)
