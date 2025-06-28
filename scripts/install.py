#!/usr/bin/env python3
"""
Installation script for WCD-Raptor
"""

import subprocess
import sys
import os

def install_requirements():
    """Install required packages"""
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✅ Requirements installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install requirements: {e}")
        sys.exit(1)

def setup_directories():
    """Setup necessary directories"""
    directories = ['output', 'logs']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ Created directory: {directory}")

def make_executable():
    """Make main script executable"""
    try:
        os.chmod('wcd_raptor.py', 0o755)
        print("✅ Made wcd_raptor.py executable")
    except Exception as e:
        print(f"⚠️  Could not make executable: {e}")

def main():
    print("🚀 Installing WCD-Raptor...")
    print("=" * 50)
    
    install_requirements()
    setup_directories()
    make_executable()
    
    print("\n" + "=" * 50)
    print("✅ WCD-Raptor installation completed!")
    print("\nUsage:")
    print("  python3 wcd_raptor.py --target https://example.com")
    print("  python3 wcd_raptor.py --url-file urls.txt")
    print("\nFor help:")
    print("  python3 wcd_raptor.py --help")

if __name__ == "__main__":
    main()
