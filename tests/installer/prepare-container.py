#!/usr/bin/env python3
"""Build fixture dependencies using official verified archives, inside image only."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

repo = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(repo / 'scripts'))
from fetch_dependencies import caddy, go

with tempfile.TemporaryDirectory(prefix='afs-image-tools-') as tmp:
    directory = Path(tmp)
    web = caddy(directory)
    compiler = go(directory)
    subprocess.run([compiler, 'build', '-mod=readonly', '-trimpath', '-o', '/opt/afs-api', '.'],
                   cwd=repo, check=True,
                   env=dict(os.environ, CGO_ENABLED='0', GOTOOLCHAIN='local'))
    shutil.copy2(web, '/opt/afs-caddy')
