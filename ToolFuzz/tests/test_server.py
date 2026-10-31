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

    def test_number_range_rejects_value_outside_bounds(self):
        command = {
            "fields": [
                {
                    "id": "risk",
                    "required": True,
                    "validation": "number_range",
                    "min": 1,
                    "max": 3,
                }
            ]
        }

        self.assertEqual(server.validate_inputs(command, {"risk": "2"}), {"risk": "2"})
        with self.assertRaises(HTTPException):
            server.validate_inputs(command, {"risk": "7"})

    def test_pattern_validation_rejects_malformed_status_codes(self):
        command = {
            "fields": [
                {
                    "id": "status_codes",
                    "required": True,
                    "pattern": r"\d{3}(,\d{3})*",
                }
            ]
        }

        self.assertEqual(
            server.validate_inputs(command, {"status_codes": "200,301,403"}),
            {"status_codes": "200,301,403"},
        )
        with self.assertRaises(HTTPException):
            server.validate_inputs(command, {"status_codes": "200; rm -rf /"})


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

    def test_sqlmap_is_marked_high_risk_and_validates_target_url(self):
        with self.assertLogs(server.logger, level="WARNING"):
            config = server.load_config()
        sqlmap = next(tool for tool in config["tools"] if tool["id"] == "sqlmap")
        target_field = sqlmap["commands"][0]["fields"][0]

        self.assertEqual(sqlmap["commands"][0]["danger"], "high")
        self.assertEqual(target_field["validation"], "private_url")

    def test_nikto_and_ffuf_load_with_private_url_targets(self):
        with self.assertLogs(server.logger, level="WARNING"):
            config = server.load_config()
        loaded_ids = {tool["id"] for tool in config["tools"]}
        self.assertIn("nikto", loaded_ids)
        self.assertIn("ffuf", loaded_ids)

        nikto = next(tool for tool in config["tools"] if tool["id"] == "nikto")
        ffuf = next(tool for tool in config["tools"] if tool["id"] == "ffuf")
        self.assertEqual(nikto["commands"][0]["fields"][0]["validation"], "private_url")
        self.assertEqual(ffuf["commands"][0]["fields"][0]["validation"], "private_url")
        wordlist_field = next(f for f in ffuf["commands"][0]["fields"] if f["id"] == "wordlist")
        self.assertEqual(wordlist_field["validation"], "local_file")

    def test_credential_cracking_tools_are_local_only_and_high_risk(self):
        with self.assertLogs(server.logger, level="WARNING"):
            config = server.load_config()
        for tool_id in ("john", "hashcat"):
            with self.subTest(tool_id=tool_id):
                tool = next(t for t in config["tools"] if t["id"] == tool_id)
                command = tool["commands"][0]
                self.assertEqual(command["danger"], "high")
                validations = {f["validation"] for f in command["fields"] if "validation" in f}
                # Solo deben operar sobre archivos locales: nada de
                # private_host/private_url/private_cidr (serían objetivos
                # de red) para herramientas que crackean hashes offline.
                self.assertTrue(validations.issubset({"local_file", "number_range"}))

    def test_wpscan_targets_private_url(self):
        with self.assertLogs(server.logger, level="WARNING"):
            config = server.load_config()
        wpscan = next(tool for tool in config["tools"] if tool["id"] == "wpscan")
        target_field = wpscan["commands"][0]["fields"][0]
        self.assertEqual(target_field["validation"], "private_url")

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
