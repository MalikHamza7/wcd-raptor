"""
Banner and branding for WCD-Raptor
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align

console = Console()

def print_banner():
    banner_text = """
██╗    ██╗ ██████╗██████╗       ██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗ 
██║    ██║██╔════╝██╔══██╗      ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██║ █╗ ██║██║     ██║  ██║█████╗██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝
██║███╗██║██║     ██║  ██║╚════╝██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗
╚███╔███╔╝╚██████╗██████╔╝      ██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║
 ╚══╝╚══╝  ╚═════╝╚═════╝       ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝
    """
    
    info_text = Text()
    info_text.append("Web Cache Deception Detection Tool\n", style="bold cyan")
    info_text.append("🔥 Now with Origin Exploitation Engine (OEE)\n", style="bold red")
    info_text.append("Developed By: ", style="white")
    info_text.append("Hamza Iqbal", style="bold green")
    info_text.append("\nVersion: ", style="white")
    info_text.append("2.0.0", style="bold yellow")
    info_text.append("\nLicense: ", style="white")
    info_text.append("MIT", style="bold blue")
    
    console.print(Panel(
        Align.center(banner_text + "\n" + str(info_text)),
        border_style="bright_blue",
        padding=(1, 2)
    ))
    console.print()
