#!/usr/bin/env python3
from ansible.module_utils.basic import AnsibleModule
import os

def _read_output():
    file_path = os.environ.get("MOCK_NETCONF_FILE", "")
    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read().rstrip("\n")
    return os.environ.get("MOCK_NETCONF_OUTPUT", "mock-netconf-output")

def main():
    module = AnsibleModule(
        argument_spec={
            "source": {"type": "str", "required": True},
            "filter": {"type": "raw", "required": False, "default": None},
        }
    )
    output = _read_output()
    module.exit_json(changed=False, stdout=output)

if __name__ == "__main__":
    main()
