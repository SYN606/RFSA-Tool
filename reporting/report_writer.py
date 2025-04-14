import os
import json
from datetime import datetime
from config.settings import CONFIG


def save_report(data, filename=None):
    """
    Saves scan report in JSON format to root-level reports/ directory.
    """
    report_dir = CONFIG.get("report_output_path", "reports")
    os.makedirs(report_dir, exist_ok=True)

    if not filename:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"report_{timestamp}.json"

    path = os.path.join(report_dir, filename)

    def sort_key(entry):
        return entry.get("criticality", 0)

    if "network_scan" in data:
        data["network_scan"] = sorted(data["network_scan"],
                                      key=sort_key,
                                      reverse=True)

    with open(path, "w") as f:
        json.dump(data, f, indent=4)

    print(f"✅ Report saved at: {path}")
