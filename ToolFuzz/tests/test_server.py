import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

import server


class ValidateInputsTests(unittest.TestCase):
    def test_private_host_rejects_public_ip(self):
        command = {
            "fields": [
                {"id": "target", "required": True, "validation": "private_host"}
            ]
        }

        with self.assertRaises(HTTPException) as error:
            server.validate_inputs(command, {"target": "8.8.8.8"})

        self.assertEqual(error.exception.status_code, 422)

    def test_private_cidr_accepts_small_private_network(self):
        command = {
            "fields": [
                {
                    "id": "target",
                    "required": True,
                    "validation": "private_cidr",
                    "max_addresses": 256,
                }
            ]
        }

        self.assertEqual(
            server.validate_inputs(command, {"target": "192.168.1.0/24"}),
            {"target": "192.168.1.0/24"},
        )

    def test_private_cidr_rejects_public_or_oversized_network(self):
        command = {
            "fields": [
                {
                    "id": "target",
                    "required": True,
                    "validation": "private_cidr",
                    "max_addresses": 256,
                }
            ]
        }

        for target in ("8.8.8.0/24", "192.168.0.0/16"):
            with self.subTest(target=target), self.assertRaises(HTTPException):
                server.validate_inputs(command, {"target": target})


class LoadConfigTests(unittest.TestCase):
    def test_high_risk_commands_are_marked_for_ui_confirmation(self):
        with self.assertLogs(server.logger, level="WARNING"):
            config = server.load_config()
        hydra = next(tool for tool in config["tools"] if tool["id"] == "hydra")

        self.assertTrue(hydra["commands"])
        self.assertTrue(all(command["danger"] == "high" for command in hydra["commands"]))

    def test_arp_scan_config_limits_private_network_size(self):
        with self.assertLogs(server.logger, level="WARNING"):
            config = server.load_config()
        arp_scan = next(tool for tool in config["tools"] if tool["id"] == "arp-scan")
        target = arp_scan["commands"][0]["fields"][0]

        self.assertEqual(target["validation"], "private_cidr")
        self.assertEqual(target["max_addresses"], 256)

    def test_invalid_tool_is_skipped_without_hiding_valid_tool(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            tools_directory = Path(temporary_directory)
            (tools_directory / "broken.json").write_text("{", encoding="utf-8")
            (tools_directory / "sample.json").write_text(
                json.dumps(
                    {
                        "id": "sample",
                        "name": "Sample",
                        "icon": "S",
                        "description": "Test tool",
                        "binary": "sample",
                        "commands": [
                            {
                                "id": "sample_command",
                                "label": "Sample command",
                                "args": [],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with patch.object(server, "TOOLS_DIR", tools_directory):
                with self.assertLogs(server.logger, level="WARNING"):
                    config = server.load_config()

        self.assertEqual([tool["id"] for tool in config["tools"]], ["sample"])
