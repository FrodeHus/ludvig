from collections import OrderedDict


def transform_finding_list(result):
    transformed = []
    for type in result:
        for r in result[type]:
            res = OrderedDict(
                [
                    ("Id", r["id"]),
                    ("Name", r["rule"]["rule_name"]),
                    ("Severity", r["severity"]),
                    ("Filename", r["filename"]),
                ]
            )
            transformed.append(res)
    return transformed


def transform_git_finding_list(result):
    transformed = []
    for type in result:
        for r in result[type]:
            res = OrderedDict(
                [
                    ("RuleId", r["rule"]["rule_id"]),
                    ("Name", r["rule"]["rule_name"]),
                    ("Severity", r["severity"]),
                    ("Filename", r["filename"]),
                    ("LineNumber", r["samples"][0]["lineNumber"]),
                    ("File SHA", r["properties"]["file_hash"]),
                    ("Commit SHA", r["properties"]["commit_hash"]),
                ]
            )
            transformed.append(res)
    return transformed
