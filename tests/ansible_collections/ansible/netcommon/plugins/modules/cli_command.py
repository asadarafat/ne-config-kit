#!/usr/bin/env python3
from ansible.module_utils.basic import AnsibleModule
import os

def _read_output():
    file_path = os.environ.get("MOCK_CLI_FILE", "")
    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read().rstrip("\n")
    return os.environ.get("MOCK_CLI_OUTPUT", "mock-cli-output")

def main():
    module = AnsibleModule(argument_spec={"command": {"type": "str", "required": True}})
    output = _read_output()
    module.exit_json(changed=False, stdout=output, stdout_lines=output.splitlines())

if __name__ == "__main__":
    main()
