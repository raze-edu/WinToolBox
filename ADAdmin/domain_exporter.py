import subprocess
import json
import os
import csv
from datetime import datetime
from typing import List, Dict, Any, Optional

class DomainExporter:
    """
    Module for accessing domain information (Users, Devices) and exporting to CSV.
    Uses PowerShell to interact with Active Directory.
    """
    def __init__(self):
        self.script_dir = os.path.join(os.path.dirname(__file__), "scripts")
        self.ad_data_script = os.path.join(self.script_dir, "get_ad_data.ps1")

    def _run_ps_script(self, script_path: str, *args) -> str:
        """
        Runs a PowerShell script and returns the stdout.
        """
        if not os.path.exists(script_path):
            raise FileNotFoundError(f"PowerShell script not found: {script_path}")

        command = [
            "powershell",
            "-ExecutionPolicy", "Bypass",
            "-NoProfile",
            "-File", script_path
        ]
        command.extend(args)

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
                encoding='utf-8',
                errors='replace' # Handle special characters gracefully
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            stdout = e.stdout.strip() if e.stdout else ""
            stderr = e.stderr.strip() if e.stderr else ""
            error_message = stderr or stdout
            raise RuntimeError(f"PowerShell script failed: {error_message}") from e

    def fetch_domain_data(self, data_type: str = "users") -> List[Dict[str, Any]]:
        """
        Fetches domain data (users or devices) from AD.
        
        Args:
            data_type: 'users' or 'devices'
            
        Returns:
            List of dictionaries containing AD object attributes.
        """
        print(f"Fetching {data_type} from Active Directory...")
        output = self._run_ps_script(self.ad_data_script, "-Type", data_type)
        
        if not output.strip():
            return []

        try:
            data = json.loads(output)
            if isinstance(data, dict):
                return [data]
            return data
        except json.JSONDecodeError as e:
            # Handle potential large output issues or encoding problems
            print(f"Error decoding JSON: {e}")
            # Try to see if there was some non-JSON output before the JSON
            if "{" in output:
                json_start = output.find("{") if "[" not in output or (output.find("{") < output.find("[")) else output.find("[")
                try:
                    return json.loads(output[json_start:])
                except:
                    pass
            raise ValueError(f"Failed to parse AD data output.")

    def export_to_csv(self, data: List[Dict[str, Any]], filename_prefix: str = "export") -> str:
        """
        Exports a list of dictionaries to a CSV file.
        Dynamically handles all keys present in the data.
        
        Args:
            data: List of AD object dictionaries.
            filename_prefix: Prefix for the generated CSV file.
            
        Returns:
            The path to the generated CSV file.
        """
        if not data:
            print("No data to export.")
            return ""

        # Collect all unique keys from all objects
        all_keys = set()
        for item in data:
            all_keys.update(item.keys())
        
        # Sort keys for consistent column ordering
        fieldnames = sorted(list(all_keys))
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{filename_prefix}_{timestamp}.csv"
        
        # Ensure we don't overwrite if we run multiple times quickly
        filepath = os.path.join(os.getcwd(), filename)
        
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')
                writer.writeheader()
                for row in data:
                    # Fill missing keys with empty string
                    clean_row = {key: row.get(key, "") for key in fieldnames}
                    writer.writerow(clean_row)
            
            print(f"Successfully exported {len(data)} records to {filepath}")
            return filepath
        except Exception as e:
            raise RuntimeError(f"Failed to write CSV: {e}")

if __name__ == "__main__":
    exporter = DomainExporter()
    try:
        # Example: Fetch and export users
        users = exporter.fetch_domain_data("users")
        if users:
            exporter.export_to_csv(users, "ad_users")
        
        # Example: Fetch and export devices
        devices = exporter.fetch_domain_data("devices")
        if devices:
            exporter.export_to_csv(devices, "ad_devices")
            
    except Exception as e:
        print(f"Error during export: {e}")
