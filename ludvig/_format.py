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
                ("Commit SHA", r["properties"]["meta"]),
            ]
        )
        transformed.append(res)
    return transformed
