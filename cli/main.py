#!/usr/bin/env python3
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.prompt import Prompt

from cli.nlp_parser import parse_command, detect_language
from cli.commands import (
    print_banner, cmd_subdomain, cmd_dns, cmd_whois, cmd_nmap,
    cmd_vuln_scan, cmd_osint, cmd_full_scan, cmd_add_target,
    cmd_list_targets, cmd_report, cmd_help
)

console = Console()

ACTION_MAP = {
    "subdomain": cmd_subdomain,
    "dns": cmd_dns,
    "whois": cmd_whois,
    "nmap": cmd_nmap,
    "xss": lambda target, **kw: cmd_vuln_scan(target, scan_types=["xss"]),
    "sqli": lambda target, **kw: cmd_vuln_scan(target, scan_types=["sqli"]),
    "ssrf": lambda target, **kw: cmd_vuln_scan(target, scan_types=["ssrf"]),
    "lfi": lambda target, **kw: cmd_vuln_scan(target, scan_types=["lfi"]),
    "redirect": lambda target, **kw: cmd_vuln_scan(target, scan_types=["redirect"]),
    "email": lambda target, **kw: cmd_osint(target),
    "social": lambda target, **kw: cmd_osint(target),
    "osint": cmd_osint,
    "full_scan": cmd_full_scan,
    "recon": cmd_full_scan,
    "add_target": cmd_add_target,
    "list_targets": lambda **kw: cmd_list_targets(),
    "report": cmd_report,
}


def dispatch(parsed: dict, raw_input: str):
    action = parsed.get("action", "unknown")
    target = parsed.get("target", "")
    lang = parsed.get("language", "en")

    if action in ("help", "مساعدة", "unknown") and not target:
        cmd_help(lang=lang)
        return

    if action == "list_targets":
        cmd_list_targets()
        return

    if action in ("report",):
        if not target:
            target = Prompt.ask("[green]Enter target[/green]")
        cmd_report(target=target)
        return

    if action in ACTION_MAP:
        if not target and action not in ("list_targets",):
            if lang == "ar":
                target = Prompt.ask("[green]أدخل الهدف (نطاق أو URL)[/green]")
            else:
                target = Prompt.ask("[green]Enter target (domain or URL)[/green]")

        if not target:
            console.print("[red]No target specified.[/red]")
            return

        fn = ACTION_MAP[action]
        try:
            fn(target=target, lang=lang)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    else:
        if lang == "ar":
            console.print(f"[yellow]لم أفهم الأمر. اكتب [bold green]مساعدة[/bold green] لعرض الأوامر.[/yellow]")
        else:
            console.print(f"[yellow]Unknown command. Type [bold green]help[/bold green] for available commands.[/yellow]")


def run():
    print_banner()
    lang = "en"

    while True:
        try:
            if lang == "ar":
                user_input = Prompt.ask("\n[bold green]OPTISEC[/bold green]").strip()
            else:
                user_input = Prompt.ask("\n[bold green]OPTISEC[/bold green]").strip()

            if not user_input:
                continue

            if user_input.lower() in ("exit", "quit", "خروج", "q"):
                console.print("[bold green]Goodbye! | وداعاً![/bold green]")
                break

            if user_input.lower() in ("web", "dashboard", "ويب"):
                console.print("[bold green]Starting web dashboard...[/bold green]")
                os.system(f"{sys.executable} -m uvicorn web.app:app --host 0.0.0.0 --port 8000 --reload")
                continue

            parsed = parse_command(user_input)
            lang = parsed.get("language", "en")

            use_ai = os.environ.get("GROQ_API_KEY") and len(user_input.split()) > 2
            if use_ai:
                try:
                    from modules.ai.groq_analyzer import natural_language_to_command
                    ai_parsed = natural_language_to_command(user_input)
                    if ai_parsed.get("confidence", 0) > 0.7:
                        parsed.update({k: v for k, v in ai_parsed.items() if v})
                except Exception:
                    pass

            dispatch(parsed, user_input)

        except KeyboardInterrupt:
            console.print("\n[bold green]Interrupted. Type 'exit' to quit.[/bold green]")
        except EOFError:
            break


if __name__ == "__main__":
    run()
