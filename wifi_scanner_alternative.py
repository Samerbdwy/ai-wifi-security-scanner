import subprocess
import sys

def install_package(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

try:
    from wifi import Cell
except ImportError:
    install_package("wifi")
    from wifi import Cell

class AdvancedWiFiScanner:
    def scan_networks(self):
        """Scan ALL nearby Wi-Fi networks using native library"""
        networks = []
        try:
            # Try common interface names
            interfaces = ['wlan0', 'wlan1', 'wlx', 'en0', 'Wi-Fi', 'en1']
            cells = []
            
            for iface in interfaces:
                try:
                    cells = Cell.all(iface)
                    if cells:
                        break
                except:
                    continue
            
            for cell in cells:
                networks.append({
                    'ssid': cell.ssid if cell.ssid else 'Hidden Network',
                    'security': cell.encryption_type if cell.encryption_type else 'Unknown',
                    'signal': f"{cell.signal} dBm",
                    'frequency': f"{cell.frequency} GHz" if cell.frequency else 'N/A',
                    'address': cell.address
                })
        except Exception as e:
            return [{"error": f"Scan failed: {str(e)}. Try running as Administrator."}]
        
        return networks