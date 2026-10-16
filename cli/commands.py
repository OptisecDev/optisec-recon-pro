import sys
import json
import asyncio
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

from modules.recon.subdomains import enumerate_subdomains
from modules.recon.dns_lookup import dns_lookup
from modules.recon.whois_lookup import whois_lookup
from modules.recon.nmap_scanner import nmap_scan
from modules.vuln.xss import scan_xss
from modules.vuln.sqli import scan_sqli
from modules.vuln.ssrf import scan_ssrf
from modules.vuln.lfi import scan_lfi
from modules.vuln.open_redirect import scan_open_redirect
from modules.vuln.crawler import crawl
from modules.osint.email_finder import find_emails
from modules.osint.social_media import find_social_profiles
from modules.target.manager import add_target, list_targets, remove_target
from modules.report.pdf_generator import generate_report
from web.scan_authz import decide, normalize_host, TRAINING_TARGETS

console = Console()


def _authorize_cli(target: str, scan_types: list):
    """Scan authorization for the CLI (web/scan_authz.py policy).

    The CLI has no user accounts, so per-domain ownership verification -- the
    thing that unlocks active checks against your own domains in the hosted
    web service (web/domain_verification.check_scan_authorization) -- isn't
    possible here. So active checks (xss/sqli/ssrf/lfi/redirect, crawl,
    nmap/ports, subdomain) run only against the hardcoded public training
    targets in web/scan_authz.TRAINING_TARGETS, each within that target's own
    permitted checks; passive checks (dns/whois/osint) run against anything.

    Returns the AuthzDecision. Prints a clear refusal naming the allowlist for
    any denied check so the user isn't left guessing. Callers run only the
    checks in `decision.allowed`.
    """
    decision = decide(target, scan_types)
    if decision.denied:
        host = normalize_host(target) or target
        console.print(f"\n[bold red]Not authorized to actively scan {host}.[/bold red]")
        if decision.reason:
            console.print(f"[red]{decision.reason}[/red]")
        console.print(
            "[yellow]The CLI runs active checks only against the public "
            "training targets:[/yellow]\n  " + ", ".join(sorted(TRAINING_TARGETS))
        )
        console.print(
            "[dim]To scan a domain you own, verify ownership in the web "
            "dashboard (type [bold]web[/bold]) and scan from there.[/dim]"
        )
    return decision

ACCENT = "[bold green]"
RESET = "[/bold green]"
ERROR = "[bold red]"


def print_banner():
    banner = f"""
[bold green]
  ██████╗ ██████╗ ████████╗██╗███████╗███████╗ ██████╗
 ██╔═══██╗██╔══██╗╚══██╔══╝██║██╔════╝██╔════╝██╔════╝
 ██║   ██║██████╔╝   ██║   ██║███████╗█████╗  ██║
 ██║   ██║██╔═══╝    ██║   ██║╚════██║██╔══╝  ██║
 ╚██████╔╝██║        ██║   ██║███████║███████╗╚██████╗
  ╚═════╝ ╚═╝        ╚═╝   ╚═╝╚══════╝╚══════╝ ╚═════╝
[/bold green]
[dim]         Recon Pro — Bug Bounty Intelligence Platform[/dim]
[dim]         Type [bold green]help[/bold green] or [bold green]مساعدة[/bold green] for commands[/dim]
"""
    console.print(banner)


def _spinner(msg: str):
    return Progress(SpinnerColumn(), TextColumn(f"[green]{msg}[/green]"), transient=True)


def cmd_subdomain(domain: str, **kwargs):
    if "subdomain" not in _authorize_cli(domain, ["subdomain"]).allowed:
        return {"subdomains": [], "unconfirmed": []}
    console.print(f"\n[bold green]Enumerating subdomains for {domain}...[/bold green]")
    result = {"subdomains": [], "unconfirmed": []}
    with _spinner(f"Scanning subdomains of {domain}") as p:
        p.add_task("scan")
        result = enumerate_subdomains(domain)

    found = result["subdomains"]
    unconfirmed = result["unconfirmed"]

    if not found:
        console.print("[yellow]No subdomains found.[/yellow]")
        if unconfirmed:
            console.print(
                f"[dim]({len(unconfirmed)} DNS record(s) resolved but failed live-host "
                f"verification — likely wildcard DNS, not real subdomains.)[/dim]"
            )
        return {"subdomains": [], "unconfirmed": unconfirmed}

    t = Table(title=f"Subdomains of {domain}", style="green")
    t.add_column("Subdomain", style="cyan")
    t.add_column("IP Address", style="white")
    for sub in found:
        t.add_row(sub["subdomain"], sub["ip"])
    console.print(t)
    console.print(f"\n[bold green]Found {len(found)} subdomains.[/bold green]")
    if unconfirmed:
        console.print(
            f"[dim]({len(unconfirmed)} additional DNS record(s) resolved but were not "
            f"confirmed as live hosts — omitted.)[/dim]"
        )
    return {"subdomains": found, "unconfirmed": unconfirmed}


def cmd_dns(domain: str, **kwargs):
    console.print(f"\n[bold green]DNS lookup for {domain}...[/bold green]")
    results = dns_lookup(domain)

    t = Table(title=f"DNS Records: {domain}", style="green")
    t.add_column("Type", style="yellow")
    t.add_column("Records", style="white")
    for rtype, values in results.items():
        if values:
            t.add_row(rtype, "\n".join(values))
    console.print(t)
    return {"dns": results}


def cmd_whois(domain: str, **kwargs):
    console.print(f"\n[bold green]WHOIS lookup for {domain}...[/bold green]")
    result = whois_lookup(domain)
    if "error" in result:
        console.print(f"[red]WHOIS error: {result['error']}[/red]")
        return result

    t = Table(title=f"WHOIS: {domain}", style="green")
    t.add_column("Field", style="yellow")
    t.add_column("Value", style="white")
    for k, v in result.items():
        if v:
            val = ", ".join(v) if isinstance(v, list) else str(v)
            t.add_row(k.replace("_", " ").title(), val)
    console.print(t)
    return {"whois": result}


def cmd_nmap(target: str, **kwargs):
    if "nmap" not in _authorize_cli(target, ["nmap"]).allowed:
        return {"nmap": {"ports": [], "error": "not authorized for this target"}}
    console.print(f"\n[bold green]Nmap scan on {target}...[/bold green]")
    with _spinner(f"Scanning ports on {target}") as p:
        p.add_task("scan")
        result = nmap_scan(target)

    if "error" in result and result["error"]:
        console.print(f"[red]Nmap error: {result['error']}[/red]")

    ports = result.get("ports", [])
    if ports:
        t = Table(title=f"Open Ports: {target}", style="green")
        t.add_column("Port", style="cyan")
        t.add_column("Protocol", style="white")
        t.add_column("Service", style="yellow")
        t.add_column("Version", style="dim")
        for port in ports:
            t.add_row(
                port.get("port", ""),
                port.get("protocol", ""),
                port.get("service", ""),
                f"{port.get('product', '')} {port.get('version', '')}".strip(),
            )
        console.print(t)
    else:
        console.print("[yellow]No open ports found or nmap not available.[/yellow]")
    return {"nmap": result}


def cmd_vuln_scan(url: str, scan_types: list = None, **kwargs):
    if not url.startswith("http"):
        url = f"https://{url}"

    scan_types = scan_types or ["xss", "sqli", "ssrf", "lfi", "redirect"]

    # Active web attacks + the crawl that feeds them run only against
    # authorized targets (web/scan_authz.py). Drop any check this target
    # isn't cleared for; if nothing is left, don't crawl or scan at all.
    allowed = _authorize_cli(url, scan_types).allowed
    scan_types = [s for s in scan_types if s in allowed]
    if not scan_types:
        return {"vulnerabilities": []}

    all_findings = []

    scanners = {
        "xss": (scan_xss, "XSS"),
        "sqli": (scan_sqli, "SQL Injection"),
        "ssrf": (scan_ssrf, "SSRF"),
        "lfi": (scan_lfi, "LFI"),
        "redirect": (scan_open_redirect, "Open Redirect"),
    }

    # One bounded, same-origin crawl feeds every vuln scanner below real
    # params/forms discovered across the target's linked pages instead of
    # each scanner guessing off `url` alone — see modules/vuln/crawler.py.
    # A failed/slow crawl must never block the scan.
    crawled_urls, crawled_forms = [], []
    console.print("[bold green]Crawling target for links/forms...[/bold green]")
    with _spinner("Crawling") as p:
        p.add_task("crawl")
        try:
            crawl_result = crawl(url)
            crawled_urls, crawled_forms = crawl_result.urls, crawl_result.forms
        except Exception as e:
            console.print(f"[yellow]Crawl failed, falling back to single-URL scan: {e}[/yellow]")

    for stype in scan_types:
        if stype in scanners:
            fn, name = scanners[stype]
            console.print(f"[bold green]Scanning for {name}...[/bold green]")
            with _spinner(f"Testing {name}") as p:
                p.add_task("scan")
                findings = fn(url, crawled_urls, crawled_forms)
            all_findings.extend(findings)

    if all_findings:
        t = Table(title=f"Vulnerabilities Found: {url}", style="green")
        t.add_column("Type", style="red")
        t.add_column("Severity", style="yellow")
        t.add_column("Parameter", style="cyan")
        t.add_column("Evidence", style="dim")
        for f in all_findings:
            t.add_row(
                f.get("type", ""),
                f.get("severity", ""),
                f.get("parameter", ""),
                f.get("evidence", "")[:60],
            )
        console.print(t)
        console.print(f"\n[bold red]Found {len(all_findings)} vulnerabilities![/bold red]")
    else:
        console.print("[green]No vulnerabilities detected.[/green]")

    return {"vulnerabilities": all_findings}


def cmd_osint(domain: str, **kwargs):
    console.print(f"\n[bold green]OSINT gathering for {domain}...[/bold green]")

    with _spinner("Finding emails") as p:
        p.add_task("scan")
        email_data = asyncio.run(find_emails(domain))

    with _spinner("Finding social profiles") as p:
        p.add_task("scan")
        social_data = asyncio.run(find_social_profiles(domain))

    if email_data.get("emails"):
        t = Table(title="Emails Found", style="green")
        t.add_column("Email", style="cyan")
        for email in email_data["emails"]:
            t.add_row(email)
        console.print(t)

    if social_data.get("profiles"):
        t = Table(title="Social Profiles", style="green")
        t.add_column("Platform", style="yellow")
        t.add_column("Handles", style="cyan")
        for platform, handles in social_data["profiles"].items():
            t.add_row(platform.title(), ", ".join(handles))
        console.print(t)

    return {"emails": email_data, "social": social_data}


def cmd_full_scan(target: str, **kwargs):
    console.print(Panel(
        f"[bold green]Starting full scan on {target}[/bold green]\n"
        "[dim]Recon → DNS → Subdomains → Nmap → Vulns → OSINT[/dim]",
        title="OPTISEC Full Scan",
        border_style="green"
    ))

    all_data = {}
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    all_data.update(cmd_dns(domain))
    all_data.update(cmd_whois(domain))
    all_data.update(cmd_subdomain(domain))
    all_data.update(cmd_nmap(domain))
    all_data.update(cmd_vuln_scan(target))
    all_data.update(cmd_osint(domain))

    return all_data


def cmd_add_target(url: str, **kwargs):
    t = add_target(url)
    console.print(f"[bold green]Target added: {t['url']} (ID: {t['id']})[/bold green]")
    return t


def cmd_list_targets(**kwargs):
    targets = list_targets()
    if not targets:
        console.print("[yellow]No targets saved yet. Use 'add <url>' to add one.[/yellow]")
        return []

    t = Table(title="Saved Targets", style="green")
    t.add_column("ID", style="dim")
    t.add_column("URL", style="cyan")
    t.add_column("Name", style="white")
    t.add_column("Added", style="dim")
    t.add_column("Scans", style="yellow")
    for target in targets:
        t.add_row(
            target.get("id", ""),
            target.get("url", ""),
            target.get("name", ""),
            target.get("added", "")[:10],
            str(len(target.get("scans", []))),
        )
    console.print(t)
    return targets


def cmd_report(target: str, data: dict = None, **kwargs):
    console.print(f"\n[bold green]Generating PDF report for {target}...[/bold green]")
    try:
        path = generate_report(
            target=target,
            recon_data=data or {},
            vuln_findings=(data or {}).get("vulnerabilities", []),
            osint_data=data or {},
        )
        console.print(f"[bold green]Report saved: {path}[/bold green]")
        return {"report_path": path}
    except Exception as e:
        console.print(f"[red]Report error: {e}[/red]")
        return {"error": str(e)}


def cmd_help(lang: str = "en", **kwargs):
    if lang == "ar":
        content = """[bold green]الأوامر المتاحة:[/bold green]

[yellow]أوامر الاستطلاع:[/yellow]
  افحص <domain>              - فحص شامل
  النطاقات الفرعية <domain> - جمع النطاقات الفرعية
  dns <domain>              - استعلام DNS
  whois <domain>            - معلومات WHOIS
  nmap <target>             - فحص المنافذ

[yellow]فحص الثغرات:[/yellow]
  xss <url>                 - فحص XSS
  sqli <url>                - فحص SQL Injection
  ssrf <url>                - فحص SSRF
  lfi <url>                 - فحص LFI
  redirect <url>            - فحص Open Redirect

[yellow]OSINT:[/yellow]
  osint <domain>            - جمع المعلومات
  ايميلات <domain>          - البحث عن إيميلات

[yellow]إدارة الأهداف:[/yellow]
  أضف <url>                 - إضافة هدف
  أهداف                    - عرض الأهداف

[yellow]التقارير:[/yellow]
  تقرير <target>            - إنشاء تقرير PDF

[yellow]أخرى:[/yellow]
  web                       - تشغيل واجهة الويب
  خروج                      - الخروج"""
    else:
        content = """[bold green]Available Commands:[/bold green]

[yellow]Recon:[/yellow]
  scan <target>             - Full scan
  subdomain <domain>        - Subdomain enumeration
  dns <domain>              - DNS lookup
  whois <domain>            - WHOIS lookup
  nmap <target>             - Port scan

[yellow]Vulnerability Scanning:[/yellow]
  xss <url>                 - XSS scan
  sqli <url>                - SQL injection scan
  ssrf <url>                - SSRF scan
  lfi <url>                 - LFI scan
  redirect <url>            - Open redirect scan

[yellow]OSINT:[/yellow]
  osint <domain>            - Gather OSINT info
  emails <domain>           - Find emails

[yellow]Target Management:[/yellow]
  add <url>                 - Add target
  targets                   - List targets

[yellow]Reports:[/yellow]
  report <target>           - Generate PDF report

[yellow]Other:[/yellow]
  web                       - Launch web dashboard
  exit / quit               - Exit"""

    console.print(Panel(content, title="OPTISEC Recon Pro — Help", border_style="green"))
