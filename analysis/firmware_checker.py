from analysis.models import SessionLocal, FirmwareSignature
from rich import print
from rich.console import Console
from rich.table import Table

console = Console()

def check_firmware(vendor, model, version, max_description_length=100):
    session = SessionLocal()
    try:
        query = session.query(FirmwareSignature).filter_by(
            vendor=vendor.lower(),
            model=model.lower(),
            version=version
        ).all()
    except Exception as e:
        print(f"[bold red]❌ Firmware DB query failed: {e}[/bold red]")
        session.close()
        return

    if not query:
        print(
            f"[bold green]✅ No known CVEs found for {vendor} {model} (v{version})[/bold green]"
        )
        session.close()
        return

    print(
        f"[bold red]⚠️ Found {len(query)} known CVE(s) for {vendor} {model} (v{version}):[/bold red]\n"
    )

    table = Table(title="CVE Vulnerability Report", style="cyan")
    table.add_column("CVE ID", style="bold magenta", no_wrap=True)
    table.add_column("Description", style="white")

    for cve in query:
        cve_id = str(cve.cve_id)
        description = str(cve.description or "")[:max_description_length]
        if len(cve.description or "") > max_description_length: # type: ignore
            description += "..."
        table.add_row(cve_id, description)

    console.print(table)
    session.close()
