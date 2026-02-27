#!/usr/bin/env python3

import json
import os
from datetime import datetime


def export_to_json(target: str, scan_results: list[dict], output_dir: str = ".") -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(".", "_")
    filename = f"scan_{safe_target}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)
    os.makedirs(output_dir, exist_ok=True)

    with open(filepath, "w") as f:
        json.dump(scan_results, f, indent=4)

    print(f"JSON report saved: {filepath}")
    return filepath
