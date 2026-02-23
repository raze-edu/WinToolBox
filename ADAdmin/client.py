import subprocess
import json
import os
from typing import List, Dict, Any

class ADClient:
    """
    Client for interacting with Azure/Entra AD using PowerShell.
    """
    def __init__(self):
        self.script_dir = os.path.join(os.path.dirname(__file__), "scripts")
        self.get_all_users_script = os.path.join(self.script_dir, "get_all_users.ps1")

    def _run_script(self, script_path: str, *args) -> str:
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
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            error_message = e.stderr.strip() if e.stderr else e.stdout.strip()
            raise RuntimeError(f"PowerShell script failed with exit code {e.returncode}: {error_message}") from e

    def get_all_users(self) -> List[Dict[str, Any]]:
        """
        Fetches all users from Azure/Entra AD, including their Manager, 
        Licenses, and Group memberships.
        
        Returns:
            A list of dictionaries containing user details.
        """
        print("Executing PowerShell script to fetch users. This may take a moment depending on directory size...")
        output = self._run_script(self.get_all_users_script)
        
        if not output.strip():
            return []

        try:
            users_data = json.loads(output)
            # Powershell ConvertTo-Json will return a dict if there's only 1 item, 
            # and a list if there are multiple.
            if isinstance(users_data, dict):
                return [users_data]
            return users_data
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON output from PowerShell: {e}\nRaw Output: {output}")

if __name__ == "__main__":
    client = ADClient()
    try:
        users = client.get_all_users()
        print(f"Successfully fetched {len(users)} users.")
        if users:
            print("First user details:")
            print(json.dumps(users[0], indent=2))
    except Exception as e:
        print(f"Error test fetching users: {e}")
