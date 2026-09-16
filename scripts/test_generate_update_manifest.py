import json
import subprocess
import tempfile
import unittest
from pathlib import Path


class GenerateUpdateManifestTest(unittest.TestCase):
    def test_generates_all_supported_targets_with_signatures(self):
        root = Path(__file__).resolve().parent
        artifacts = {
            "macos-arm64-AgentVeil.app.tar.gz": "mac-arm",
            "macos-amd64-AgentVeil.app.tar.gz": "mac-intel",
            "linux-amd64-AgentVeil.AppImage": "linux",
            "windows-amd64-AgentVeil-setup.exe": "windows",
        }
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            for name, signature in artifacts.items():
                path = directory / f"agentveil-1.2.3-dev-{name}"
                path.touch()
                Path(f"{path}.sig").write_text(signature + "\n", encoding="utf-8")
            output = directory / "latest.json"
            subprocess.run(
                [
                    "python3",
                    str(root / "generate-update-manifest.py"),
                    "--artifacts", str(directory),
                    "--repository", "EverEcho/agent-veil",
                    "--channel", "dev",
                    "--version", "1.2.3",
                    "--tag", "v1.2.3-dev",
                    "--output", str(output),
                ],
                check=True,
            )
            manifest = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(manifest["version"], "1.2.3")
            self.assertEqual(
                set(manifest["platforms"]),
                {"darwin-aarch64", "darwin-x86_64", "linux-x86_64", "windows-x86_64"},
            )
            self.assertEqual(manifest["platforms"]["linux-x86_64"]["signature"], "linux")


if __name__ == "__main__":
    unittest.main()
