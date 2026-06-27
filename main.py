#!/usr/bin/env python3
"""OPTISEC Recon Pro — Entry point"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import click
from rich.console import Console

console = Console()


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """OPTISEC Recon Pro — Bug Bounty Intelligence Platform"""
    if ctx.invoked_subcommand is None:
        from cli.main import run
        run()


@cli.command()
@click.option("--host", default="0.0.0.0", help="Host to bind")
@click.option("--port", default=8000, help="Port to bind")
@click.option("--reload", is_flag=True, default=False, help="Auto-reload")
def web(host, port, reload):
    """Launch the web dashboard"""
    import uvicorn
    console.print(f"[bold green]Starting OPTISEC Web Dashboard on http://{host}:{port}[/bold green]")
    uvicorn.run("web.app:app", host=host, port=port, reload=reload)


@cli.command()
@click.argument("target")
@click.option("--type", "scan_type", default="full",
              type=click.Choice(["full", "subdomain", "dns", "whois", "nmap", "xss", "sqli", "ssrf", "lfi", "redirect", "osint"]),
              help="Scan type")
@click.option("--output", "-o", default=None, help="Save JSON output to file")
def scan(target, scan_type, output):
    """Run a scan from the command line"""
    import json
    from cli.commands import (cmd_subdomain, cmd_dns, cmd_whois, cmd_nmap,
                               cmd_vuln_scan, cmd_osint, cmd_full_scan)

    scanners = {
        "subdomain": cmd_subdomain,
        "dns": cmd_dns,
        "whois": cmd_whois,
        "nmap": cmd_nmap,
        "xss": lambda target, **kw: cmd_vuln_scan(target, scan_types=["xss"]),
        "sqli": lambda target, **kw: cmd_vuln_scan(target, scan_types=["sqli"]),
        "ssrf": lambda target, **kw: cmd_vuln_scan(target, scan_types=["ssrf"]),
        "lfi": lambda target, **kw: cmd_vuln_scan(target, scan_types=["lfi"]),
        "redirect": lambda target, **kw: cmd_vuln_scan(target, scan_types=["redirect"]),
        "osint": cmd_osint,
        "full": cmd_full_scan,
    }

    result = scanners[scan_type](target=target)

    if output:
        with open(output, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        console.print(f"[bold green]Results saved to {output}[/bold green]")


@cli.command()
@click.argument("target")
@click.option("--scan-id", default="", help="Scan ID to include results from")
def report(target, scan_id):
    """Generate a PDF report"""
    from cli.commands import cmd_report
    cmd_report(target=target)


@cli.command()
def targets():
    """List saved targets"""
    from cli.commands import cmd_list_targets
    cmd_list_targets()


@cli.command()
@click.argument("url")
@click.option("--name", default="", help="Target name")
def add(url, name):
    """Add a target"""
    from cli.commands import cmd_add_target
    cmd_add_target(target=url)


if __name__ == "__main__":
    cli()
