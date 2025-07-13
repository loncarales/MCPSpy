#!/usr/bin/env python3
"""
End-to-End Test Utility for MCPSpy
================================

This utility tests MCPSpy by running it in background, generating MCP traffic,
and validating the captured JSONL output against expected test cases.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from deepdiff import DeepDiff


class MCPSpyE2ETest:
    """End-to-end test runner for MCPSpy."""

    def __init__(self, mcpspy_path: str = "../mcpspy"):
        self.mcpspy_path = mcpspy_path
        self.python_executable = sys.executable  # Use the same Python interpreter
        self.mcpspy_process: Optional[subprocess.Popen] = None
        self.output_file: Optional[str] = None

    def run_test(self) -> bool:
        """Run the complete end-to-end test. Returns True if all tests pass."""
        try:
            print("Starting end-to-end test")

            # Create temporary output file
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".jsonl", delete=False
            ) as f:
                self.output_file = f.name

            print(f"Output file: {self.output_file}")

            # Start MCPSpy in background
            self._start_mcpspy()

            # Wait for eBPF initialization
            print("Waiting for eBPF initialization...")
            time.sleep(2)

            # Run MCP client to generate traffic
            self._run_mcp_client()

            # Stop MCPSpy
            self._stop_mcpspy()

            # Validate output
            return self._validate_output()

        except Exception as e:
            print(f"Test failed with error: {e}")
            return False
        finally:
            self._cleanup()

    def _start_mcpspy(self) -> None:
        """Start MCPSpy process in background."""
        cmd = ["sudo", self.mcpspy_path, "--output", self.output_file]
        print(f"Starting MCPSpy: {' '.join(cmd)}")

        self.mcpspy_process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid
        )

    def _stop_mcpspy(self) -> None:
        """Stop MCPSpy process."""
        if self.mcpspy_process:
            print("Stopping MCPSpy...")
            try:
                # Send SIGINT to the process group
                os.killpg(os.getpgid(self.mcpspy_process.pid), signal.SIGINT)
                self.mcpspy_process.wait(timeout=5)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                # Force kill if it doesn't respond
                try:
                    os.killpg(os.getpgid(self.mcpspy_process.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def _run_mcp_client(self) -> None:
        """Run the MCP client to generate test traffic."""
        client_script = Path(__file__).parent / "mcp_client.py"
        server_script = Path(__file__).parent / "mcp_server.py"

        if not client_script.exists():
            raise FileNotFoundError(f"MCP client script not found: {client_script}")
        if not server_script.exists():
            raise FileNotFoundError(f"MCP server script not found: {server_script}")

        cmd = [
            self.python_executable,
            str(client_script),
            "--server",
            f"{self.python_executable} {server_script}",
        ]

        print(f"Running MCP client: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            print(f"MCP client stderr: {result.stderr}")
            raise RuntimeError(f"MCP client failed with code {result.returncode}")

        print("MCP client completed successfully")

    def _validate_output(self) -> bool:
        """Validate the JSONL output against expected test cases using deepdiff."""

        # Captured data
        if not os.path.exists(self.output_file):
            print("Output file does not exist")
            return False

        captured_messages = self._read_jsonl_file(self.output_file)
        if not captured_messages:
            print("No messages captured")
            return False

        print(f"Captured {len(captured_messages)} messages")

        # Expected data
        expected_file = Path(__file__).parent / "expected_output.jsonl"
        if not expected_file.exists():
            print(f"Expected output file not found: {expected_file}")
            return False

        expected_patterns = self._read_jsonl_file(expected_file)
        if not expected_patterns:
            print("No expected patterns found")
            return False

        print(f"Expected {len(expected_patterns)} patterns")

        # Ignoring dynamic fields, like timestamp, and pid.
        exclude_regex_paths = [
            r"root\[\d+\]\['timestamp'\]",
            r"root\[\d+\]\['stdio_transport'\]\['from_pid'\]",
            r"root\[\d+\]\['stdio_transport'\]\['to_pid'\]",
        ]

        diff = DeepDiff(
            expected_patterns,
            captured_messages,
            ignore_order=False,
            exclude_regex_paths=exclude_regex_paths,
        )
        if not diff:
            print("All messages match expected output!")
            return True
        else:
            print("Output differs from expected:")
            print("\n=== Comparison Results ===")
            print(diff.pretty())

            return False

    def _read_jsonl_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Read and parse a JSONL file."""
        messages = []
        try:
            with open(file_path, "r") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        message = json.loads(line)
                        messages.append(message)
                    except json.JSONDecodeError as e:
                        print(f"Failed to parse JSON on line {line_num}: {e}")
        except FileNotFoundError:
            print(f"JSONL file not found: {file_path}")
        return messages

    def _cleanup(self) -> None:
        """Clean up temporary files and processes."""
        pass
        # if self.mcpspy_process:
        #     self._stop_mcpspy()

        # if self.output_file and os.path.exists(self.output_file):
        #     try:
        #         os.unlink(self.output_file)
        #         print(f"Cleaned up output file: {self.output_file}")
        #     except OSError:
        #         pass


def main():
    parser = argparse.ArgumentParser(description="End-to-end test for MCPSpy")
    parser.add_argument(
        "--mcpspy",
        default="../mcpspy",
        help="Path to MCPSpy binary (default: ../mcpspy)",
    )

    args = parser.parse_args()

    if not os.path.exists(args.mcpspy):
        print(f"Error: MCPSpy binary not found: {args.mcpspy}")
        print("Build it first with: make build")
        sys.exit(1)

    # Check if running as root (required for eBPF)
    if os.geteuid() != 0:
        print("Error: This test must be run as root (required for eBPF)")
        print("Run with: sudo python tests/e2e_test.py")
        sys.exit(1)

    test = MCPSpyE2ETest(args.mcpspy)
    success = test.run_test()

    if success:
        print("✅ All tests passed!")
        sys.exit(0)
    else:
        print("🚫 Some tests failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
