"""
Sekoia Automation Action for Google Threat Intelligence: Scan File
"""

from sekoia_automation.action import Action
from .client import VTAPIConnector
import vt
from pathlib import Path


class GTIScanFile(Action):
    """
    Upload a file to Google Threat Intelligence (VirusTotal) for scanning
    """

    def run(self, arguments: dict):
        try:
            api_key = self.module.configuration.get("api_key")
            if not api_key:
                return {"success": False, "error": "API key not configured"}

            rel_path = arguments.get("file_path")
            if not rel_path:
                return {"success": False, "error": "Missing argument: file_path"}

            file_path = self.data_path.joinpath(rel_path)

            if not file_path.exists() or not file_path.is_file():
                return {"success": False, "error": f"File not found in data storage: {rel_path}"}

            connector = VTAPIConnector(api_key, url="", domain="", ip="", file_hash="", cve="")

            with vt.Client(api_key, trust_env=True) as client:
                connector.scan_file(client, str(file_path))
                if not connector.results:
                    return {"success": False, "error": "No scan results returned by VT connector"}

                last_result = connector.results[-1]
                analysis = last_result.response
                if analysis is None:
                    return {"success": False, "error": last_result.error or "Scan failed with empty response"}

                return {
                    "success": True,
                    "data": {
                        "analysis_stats": analysis.get("analysis_stats"),
                        "analysis_results": analysis.get("analysis_results"),
                        "file_path": analysis.get("file_path", rel_path),
                    },
                }
        except Exception as e:
            return {"success": False, "error": str(e)}
