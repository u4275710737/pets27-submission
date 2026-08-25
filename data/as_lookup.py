import os
import json
import pytricia

_pyt = None
_meta = {}


def _read_ases():
    global _pyt, _meta

    base_folder = "./as-ip-blocks/as/"
    _pyt = pytricia.PyTricia()

    for asn_dir in os.listdir(base_folder):
        json_path = os.path.join(base_folder, asn_dir, "aggregated.json")
        if not os.path.isfile(json_path):
            continue
        with open(json_path) as f:
            data = json.load(f)

        asn = data["asn"]
        meta = data.get("metadata", {}) or {}
        description = meta.get("description") or meta.get("handle")
        _meta[asn] = description

        for net in data.get("prefixes", {}).get("ipv4", []):
            _pyt[net] = asn


_read_ases()


def as_of(addr):
    """Returns (asn, description) tuple for the given address (longest-prefix-match), or None."""
    try:
        asn = _pyt.get(addr)
    except KeyError:
        return None
    if asn is None:
        return None
    return asn, _meta.get(asn)