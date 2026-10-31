import unittest

import server


class CoreToolConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with unittest.TestCase().assertLogs(server.logger, level="WARNING"):
            cls.tools = {tool["id"]: tool for tool in server.load_config()["tools"]}

    def test_nmap_targets_are_private_hosts_and_have_runtime_limits(self):
        nmap = self.tools["nmap"]

        for command in nmap["commands"]:
            with self.subTest(command=command["id"]):
                target = next(field for field in command["fields"] if field["id"] == "target")
                self.assertEqual(target["validation"], "private_host")
                self.assertLessEqual(command["runtime_seconds"], 600)

        command = nmap["commands"][0]
        with self.assertRaises(server.HTTPException):
            server.validate_inputs(command, {"target": "8.8.8.8"})

    def test_whois_is_domain_only_read_only_lookup_with_runtime_limit(self):
        whois = self.tools["whois"]
        command = whois["commands"][0]
        domain = command["fields"][0]

        self.assertEqual(domain["validation"], "domain")
        self.assertEqual(command["args"], ["{domain}"])
        self.assertLessEqual(command["runtime_seconds"], 60)
        self.assertEqual(
            server.validate_inputs(command, {"domain": "example.com"}),
            {"domain": "example.com"},
        )

    def test_whatweb_uses_kali_binary_and_low_aggression(self):
        whatweb = self.tools["whatweb"]
        command = whatweb["commands"][0]
        url = command["fields"][0]

        self.assertEqual(whatweb["binary"], "whatweb")
        self.assertNotIn("entrypoint", whatweb)
        self.assertEqual(url["validation"], "private_url")
        self.assertIn("--aggression", command["args"])
        self.assertIn("1", command["args"])
        self.assertLessEqual(command["runtime_seconds"], 60)
        with self.assertRaises(server.HTTPException):
            server.validate_inputs(command, {"url": "https://example.com/"})

    def test_gobuster_accepts_private_https_url_and_bounds_concurrency(self):
        gobuster = self.tools["gobuster"]
        command = gobuster["commands"][0]
        fields = {field["id"]: field for field in command["fields"]}

        self.assertEqual(fields["target"]["validation"], "private_url")
        self.assertEqual(fields["wordlist"]["validation"], "local_file")
        self.assertIn("{target}", command["args"])
        self.assertNotIn("http://{target}", command["args"])
        self.assertIn("10", command["args"])
        self.assertIn("10s", command["args"])
        self.assertLessEqual(command["runtime_seconds"], 300)
        values = server.validate_inputs(
            command,
            {"target": "https://192.168.1.10:8443/app/", "wordlist": __file__},
        )
        self.assertEqual(
            server.build_args(gobuster, command, values),
            [
                "gobuster",
                "dir",
                "-u",
                "https://192.168.1.10:8443/app/",
                "-w",
                __file__,
                "--threads",
                "10",
                "--timeout",
                "10s",
            ],
        )
        with self.assertRaises(server.HTTPException):
            server.validate_inputs(
                command,
                {"target": "https://example.com/", "wordlist": __file__},
            )
