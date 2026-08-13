import asyncio
import sys
from typing import Optional
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from cerberus.auth import DomainVerifier
from cerberus.crawler import AsyncScannerEngine
from cerberus.rules.headers import SecurityHeadersRule

app = typer.Typer(
    name="Cerberus AppSec",
    help="AI-driven, consent-first web application security scanner.",
    add_completion=False,
)

console = Console()


def _extract_domain(url: str) -> str:
    """Extracts the netloc/domain from a target URL."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    parsed = urlparse(url)
    if not parsed.netloc:
        console.print("[bold red]Error:[/bold red] Invalid URL provided.")
        raise typer.Exit(code=1)
    return parsed.netloc


async def _run_verification_flow(target_domain: str, skip_auth: bool = False) -> bool:
    """
    Enforces pre-scan domain ownership verification.
    Returns True if verified or explicitly skipped in local dev mode.
    """
    if skip_auth:
        console.print(
            "[bold yellow]⚠️  WARNING:[/bold yellow] Skipping authorization verification (--skip-auth). "
            "Ensure you have explicit written permission before scanning!"
        )
        return True

    verifier = DomainVerifier()
    challenge = verifier.generate_challenge(target_domain)

    # Render Challenge Instructions Panel
    instructions = (
        f"[bold cyan]Target Domain:[/bold cyan] [underline]{target_domain}[/underline]\n\n"
        f"To proceed, prove domain ownership using [bold]ONE[/bold] of the following options:\n\n"
        f"[bold white]Option A — DNS TXT Record:[/bold white]\n"
        f"  Add a TXT record to [cyan]{target_domain}[/cyan]:\n"
        f"  [bold yellow]{challenge.expected_txt_record}[/bold yellow]\n\n"
        f"[bold white]Option B — HTTP File Upload:[/bold white]\n"
        f"  Host a plain-text file at:\n"
        f"  [cyan]https://{target_domain}{challenge.expected_file_path}[/cyan]\n"
        f"  File Content:\n"
        f"  [bold yellow]{challenge.token}[/bold yellow]"
    )

    console.print(
        Panel(
            instructions,
            title="[bold red]🔒 CONSENT VERIFICATION REQUIRED[/bold red]",
            border_style="red",
            expand=False,
        )
    )

    if not Confirm.ask("Have you configured DNS or HTTP verification?"):
        console.print("[yellow]Scan canceled by user.[/yellow]")
        return False

    with console.status("[bold blue]Checking domain authorization...[/bold blue]"):
        # 1. Try DNS TXT Check
        dns_success, dns_msg = verifier.verify_dns_txt(target_domain, challenge.token)
        if dns_success:
            console.print(f"[bold green]✓ Authorization Granted:[/bold green] {dns_msg}")
            return True

        # 2. Fallback to HTTP File Check
        http_success, http_msg = await verifier.verify_http_file(
            target_domain, challenge.token
        )
        if http_success:
            console.print(f"[bold green]✓ Authorization Granted:[/bold green] {http_msg}")
            return True

    # Verification Failed
    console.print("\n[bold red]❌ Authorization Failed![/bold red]")
    console.print(f"  • DNS:  {dns_msg}")
    console.print(f"  • HTTP: {http_msg}")
    console.print(
        "\n[bold yellow]Aborting scan.[/bold yellow] Cerberus AppSec requires verified target consent."
    )
    return False


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL to scan (e.g., https://example.com)"),
    depth: int = typer.Option(2, "--depth", "-d", help="Maximum crawling depth"),
    concurrency: int = typer.Option(
        5, "--concurrency", "-c", help="Max concurrent HTTP requests"
    ),
    skip_auth: bool = typer.Option(
        False,
        "--skip-auth",
        help="Bypass consent check (USE ONLY FOR AUTHORIZED LOCAL/STAGING TESTS)",
    ),
):
    """
    Perform a consent-verified security scan against an authorized target.
    """
    console.print("\n[bold magenta] Cerberus AppSec Scanner v0.1.0[/bold magenta]\n")

    target_domain = _extract_domain(url)
    target_url = url if url.startswith(("http://", "https://")) else f"https://{url}"

    # 1. Verification Phase
    verified = asyncio.run(_run_verification_flow(target_domain, skip_auth=skip_auth))
    if not verified:
        raise typer.Exit(code=1)

    # 2. Execution Phase
    console.print(
        f"\n[bold green]Initiating Scan Target:[/bold green] {target_url} (Depth: {depth}, Concurrency: {concurrency})"
    )

    rules = [
        SecurityHeadersRule(),
        # Add additional rule plugins here
    ]

    engine = AsyncScannerEngine(
        target_url=target_url,
        rules=rules,
        max_depth=depth,
        concurrency=concurrency,
    )

    with console.status("[bold blue]Crawling application and running detection engine...[/bold blue]"):
        findings = asyncio.run(engine.crawl_and_scan())

    # 3. Results Output
    if not findings:
        console.print(
            "\n[bold green]✓ Scan Complete![/bold green] No security findings detected."
        )
        return

    table = Table(title=f"\nSecurity Assessment Results ({len(findings)} Findings)")
    table.add_column("Severity", style="bold", justify="center")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Finding Title")
    table.add_column("Affected Endpoint")

    for finding in findings:
        severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        
        if severity in ["HIGH", "CRITICAL"]:
            sev_style = f"[bold red]{severity}[/bold red]"
        elif severity == "MEDIUM":
            sev_style = f"[yellow]{severity}[/yellow]"
        else:
            sev_style = f"[blue]{severity}[/blue]"

        table.add_row(sev_style, finding.rule_id, finding.title, finding.url)

    console.print(table)


if __name__ == "__main__":
    app()