"""Shared paths and metadata for the recorded experiment collections."""
from pathlib import Path
import hashlib,json

ROOT=Path(__file__).resolve().parents[1]
def load(path):
    with path.open(encoding='utf-8') as stream:return json.load(stream)
def catalog():return load(ROOT/'experiments/catalog.json')
def study(name):
    available={x['id']:x for x in catalog()['studies']}
    if name not in available:raise ValueError(f"Unknown collection {name!r}; choose {', '.join(available)}")
    folder=ROOT/'experiments'/name
    return folder,load(folder/'manifest.json')
def digest(data):return hashlib.sha256(data).hexdigest()
