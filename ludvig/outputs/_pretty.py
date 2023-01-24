from typing import List
from rich.table import Table
from ludvig.types import Finding, Severity
from rich.console import Console

class PrettyConsole:
    def __init__(self, findings : List[Finding]) -> None:
        self.findings = findings
    
    def output(self):
        table = Table(title="Findings", show_lines=True)
        table.add_column("Rule", style="white")
        table.add_column("Filename", style="white", overflow="fold")
        table.add_column("Content", style="red")
        for finding in self.findings:
            table.add_row(
                "{}: {}\r\n[gray50]{}[/]".format(
                    self.__color_coded_severity(finding.match.severity),
                    finding.match.rule_name,
                    ", ".join(finding.match.tags),
                ),
                "{} {}\r\n[gray50]{}{}[/]".format(
                    finding.filename,
                    (":cross_mark:" if finding.whiteout else ""),
                    "Created by: [yellow]{}[/]".format(self.__prettify(finding.comment)),
                    "\r\nRemoved by: [yellow]{}[/]".format(self.__prettify(finding.removed_by))
                    if finding.removed_by
                    else "",
                ),
                self.__format_samples(finding),
            )

        console = Console()
        console.print(table)
    def __format_samples(self, finding: Finding):
        output = ""
        for sample in finding.samples:
            output += "[yellow]{0:<5d}[/]: {1}\r\n".format(
                sample.offset, sample.content
            )
        return output


    def __prettify(self, s: str) -> str:
        if s is None:
            return s
        s = s[: s.index("#") if "#" in s else len(s)]
        return s.replace("/bin/sh -c", "")


    def __color_coded_severity(self, severity: Severity):
        match severity:
            case "MEDIUM":
                return "[yellow]{0:<10s}[/]".format(severity)
            case "HIGH":
                return "[magenta]{0:<10s}[/]".format(severity)
            case "CRITICAL":
                return "[red]{0:<10s}[/]".format(severity)
            case _:
                return "[bright_black]{0:<10s}[/]".format(severity)
