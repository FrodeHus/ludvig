from collections import OrderedDict
import sys
from ludvig.types import Severity
from knack import CLI, ArgumentsContext, CLICommandsLoader
from knack.commands import CommandGroup
import ludvig._help  # pylint: disable=unused-import
from ludvig._format import transform_finding_list


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
        return OrderedDict(self.command_table)

    def load_arguments(self, command):
        with ArgumentsContext(self, "image") as ac:
            ac.argument(
                "severity_level", choices=[e.name for e in Severity], default="MEDIUM"
            )
        with ArgumentsContext(self, "fs") as ac:
            ac.argument(
                "severity_level", choices=[e.name for e in Severity], default="MEDIUM"
            )
        super(LudvigCommandsLoader, self).load_arguments(command)


ludvig_cli = CLI(cli_name="ludvig", commands_loader_cls=LudvigCommandsLoader)
exit_code = ludvig_cli.invoke(sys.argv[1:])
sys.exit(exit_code)
