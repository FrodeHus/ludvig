from collections import OrderedDict
import sys
from ludvig import Severity
from knack import CLI, ArgumentsContext, CLICommandsLoader
from knack.commands import CommandGroup
from knack.invocation import CommandInvoker
import ludvig._help  # noqa
from ludvig._format import transform_finding_list, transform_git_finding_list


class LudvigCommandsLoader(CLICommandsLoader):
    def load_command_table(self, args):
        with CommandGroup(
            self, "image", "ludvig.commands.image#{}", help="Container image operations"
        ) as g:
            g.command("scan", "scan", table_transformer=transform_finding_list)
        with CommandGroup(
            self, "fs", "ludvig.commands.filesystem#{}", help="File system operations"
        ) as g:
            g.command("scan", "scan", table_transformer=transform_finding_list)
        with CommandGroup(self, "git", "ludvig.commands.git#{}") as g:
            g.command("scan", "scan", table_transformer=transform_git_finding_list)
        with CommandGroup(self, "rules", "ludvig.commands.rules#{}") as g:
            g.command("download", "download")
            g.command("add repo", "add_repo")
        with CommandGroup(self, "vulndb", "ludvig.commands.vulndb#{}") as g:
            g.command("add osv", "add_osv_repository")
        return OrderedDict(self.command_table)

    def load_arguments(self, command):
        with ArgumentsContext(self, "image") as ac:
            ac.argument(
                "severity_level", choices=[e.name for e in Severity], default="MEDIUM"
            )
            ac.argument("max_file_size", type=int)
            ac.argument(
                "enabled", choices=["secret", "vuln"], default="secret vuln", nargs="+"
            )
        with ArgumentsContext(self, "fs") as ac:
            ac.argument(
                "severity_level", choices=[e.name for e in Severity], default="MEDIUM"
            )
            ac.argument("max_file_size", type=int)
            ac.argument(
                "enabled", choices=["secret", "vuln"], default="secret vuln", nargs="+"
            )
        with ArgumentsContext(self, "git") as ac:
            ac.argument(
                "severity_level", choices=[e.name for e in Severity], default="MEDIUM"
            )
            ac.argument("max_file_size", type=int)
            ac.argument(
                "enabled", choices=["secret", "vuln"], default="secret vuln", nargs="+"
            )
        super(LudvigCommandsLoader, self).load_arguments(command)


class LudvigCommandInvoker(CommandInvoker):
    def execute(self, args):
        result = super().execute(args)
        if (
            len(args) > 1 and args[1] == "scan" and result.result
        ):  # dirty hack to provoke exit code if any scan results return
            result.exit_code = 1
        return result


ludvig_cli = CLI(
    cli_name="ludvig",
    commands_loader_cls=LudvigCommandsLoader,
    invocation_cls=LudvigCommandInvoker,
)
exit_code = ludvig_cli.invoke(sys.argv[1:])
sys.exit(exit_code)
