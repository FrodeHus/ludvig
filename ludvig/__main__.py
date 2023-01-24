from collections import OrderedDict
import sys
from ludvig.types import Severity
from knack import CLI, ArgumentsContext, CLICommandsLoader
from knack.commands import CommandGroup


class LudvigCommandsLoader(CLICommandsLoader):
    def load_command_table(self, args):
        with CommandGroup(self, "image", "ludvig.commands.image#{}") as g:
            g.command("scan", "scan")
        with CommandGroup(self, "fs", "ludvig.commands.filesystem#{}") as g:
            g.command("scan", "scan")
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
