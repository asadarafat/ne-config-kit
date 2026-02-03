#!/usr/bin/env python3
from ansible.module_utils.basic import AnsibleModule
import os

def main():
    module = AnsibleModule(
        argument_spec={
            "target": {"type": "str", "required": True},
            "content": {"type": "str", "required": True},
            "default_operation": {"type": "str", "default": "merge"},
        },
        supports_check_mode=True,
    )

    log_path = os.environ.get("NETCONF_CONFIG_LOG", "")
    if log_path:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(module.params["content"])
            f.write("\n")

    if module.check_mode:
        module.exit_json(changed=False)

    module.exit_json(changed=True)

if __name__ == "__main__":
    main()
