"""Punto de entrada del CLI de bazzingakit."""

import click

from bazzingakit import __version__
from bazzingakit.cli.commands import ai as ai_cmd
from bazzingakit.cli.commands import config as config_cmd
from bazzingakit.cli.commands import device as device_cmd
from bazzingakit.cli.commands import frida as frida_cmd
from bazzingakit.cli.commands import ios as ios_cmd
from bazzingakit.cli.commands import playbook as playbook_cmd
from bazzingakit.cli.commands import proxy as proxy_cmd
from bazzingakit.cli.commands import rasp as rasp_cmd
from bazzingakit.cli.commands import scripts as scripts_cmd
from bazzingakit.cli.commands import session as session_cmd
from bazzingakit.cli.commands import tui as tui_cmd
from bazzingakit.cli.commands.analyze import analyze, run
from bazzingakit.cli.commands.doctor import doctor as doctor_cmd
from bazzingakit.cli.commands.investigate import investigate as investigate_cmd
from bazzingakit.cli.commands.objection import objection as objection_cmd
from bazzingakit.utils import setup_logging


@click.group()
@click.version_option(version=__version__, prog_name="bazzingakit")
@click.option(
    "--log-level",
    default="INFO",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    help="Nivel de logging",
)
@click.pass_context
def cli(ctx: click.Context, log_level: str) -> None:
    """Bazzingakit: framework de análisis de seguridad móvil."""
    setup_logging(level=log_level)
    ctx.ensure_object(dict)


# Comandos top-level
cli.add_command(analyze)
cli.add_command(run)
cli.add_command(investigate_cmd)
cli.add_command(objection_cmd)
# Alias corto
cli.add_command(objection_cmd, name="obj")
cli.add_command(doctor_cmd)
cli.add_command(tui_cmd.tui)

# Grupos
cli.add_command(config_cmd.config)
cli.add_command(ai_cmd.ai)
cli.add_command(session_cmd.session)
cli.add_command(device_cmd.device)
cli.add_command(frida_cmd.frida)
cli.add_command(ios_cmd.ios)
cli.add_command(scripts_cmd.scripts)
cli.add_command(playbook_cmd.playbook)
cli.add_command(proxy_cmd.proxy)
cli.add_command(rasp_cmd.rasp)


if __name__ == "__main__":
    cli()
