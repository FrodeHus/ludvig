import json


def parse_package_lock(lock_file: str):
    try:
        lock_data = json.loads(lock_file)
    except json.JSONDecodeError:
        return []

    packages = []
    for item in [p for p in lock_data["packages"] if p.startswith("node_modules")]:
        name = item[item.find("/") + 1 :]
        version = lock_data["packages"][item]["version"]
        packages.append({"ecosystem": "npm", "name": name, "version": version})

    return packages
