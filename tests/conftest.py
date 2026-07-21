"""Fixtures: repositórios de teste com workflows vulnerável e endurecido."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ["COLUMNS"] = "200"

VULN_WORKFLOW = """\
name: vuln
on: pull_request_target
permissions: write-all
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - uses: some-org/some-action@v1
      - name: build
        run: |
          echo "titulo: ${{ github.event.issue.title }}"
          curl https://exemplo.invalid/install.sh | bash
          echo "token=${{ secrets.API_TOKEN }}"
"""

SAFE_WORKFLOW = """\
name: safe
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: build
        run: echo "ola"
"""


def _write_repo(base: Path, name: str, content: str) -> Path:
    wf_dir = base / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / name).write_text(content, encoding="utf-8")
    return base


@pytest.fixture
def vuln_repo(tmp_path: Path) -> Path:
    return _write_repo(tmp_path, "vuln.yml", VULN_WORKFLOW)


@pytest.fixture
def safe_repo(tmp_path: Path) -> Path:
    return _write_repo(tmp_path, "safe.yml", SAFE_WORKFLOW)
