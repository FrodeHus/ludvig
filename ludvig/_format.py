from collections import OrderedDict


def transform_finding_list(result):
    transformed = []
    for r in result:
        res = OrderedDict(
            [
                ("RuleId", r["match"]["id"]),
                ("Name", r["match"]["ruleName"]),
                ("Severity", r["severity"]),
                ("Filename", r["filename"]),
                ("LineNumber", r["samples"][0]["lineNumber"]),
            ]
        )
        transformed.append(res)
    return transformed


def transform_git_finding_list(result):
    transformed = []
    for r in result:

        res = OrderedDict(
            [
                ("RuleId", r["match"]["id"]),
                ("Name", r["match"]["ruleName"]),
                ("Severity", r["severity"]),
                ("Filename", r["filename"]),
                ("LineNumber", r["samples"][0]["lineNumber"]),
                ("File SHA", r["properties"]["file_hash"]),
                ("Commit SHA", r["properties"]["commit_hash"]),
            ]
        )
        transformed.append(res)
    return transformed
