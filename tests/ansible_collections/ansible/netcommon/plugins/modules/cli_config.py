#!/usr/bin/env python3
from ansible.module_utils.basic import AnsibleModule
import os

def main():
    module = AnsibleModule(
        argument_spec={
            "config": {"type": "str", "required": True},
            "replace": {"type": "str", "default": "line"},
            "diff_match": {"type": "str", "default": "line"},
            "save_when": {"type": "str", "default": "never"},
        },
        supports_check_mode=True,
    )

    log_path = os.environ.get("CLI_CONFIG_LOG", "")
    if log_path:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(module.params["config"])
            f.write("\n")

    if module.check_mode:
        module.exit_json(changed=False)

    module.exit_json(changed=True)

if __name__ == "__main__":
    main()
