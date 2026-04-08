import subprocess
import re
import platform
import time

class WiFiScanner:
    def __init__(self, debug=False):
        self.os_type = platform.system()
        self.debug = debug
    
    def scan_networks(self):
        """Scan for nearby Wi-Fi networks"""
        networks = []
        
        if self.debug:
            print(f"[DEBUG] OS detected: {self.os_type}")
        
        try:
            if self.os_type == "Windows":
                # Get current SSID before disconnecting
                current_ssid = self._get_current_ssid()
                
                if self.debug:
                    print(f"[DEBUG] Current SSID: {current_ssid}")
                
                # Only disconnect if connected (to force fresh scan)
                if current_ssid:
                    if self.debug:
                        print(f"[DEBUG] Disconnecting from {current_ssid} to force fresh scan...")
                    
                    # Disconnect from current network
                    subprocess.run(
                        ["netsh", "wlan", "disconnect"],
                        capture_output=True, text=True
                    )
                    
                    # Wait for disconnect and fresh scan
                    time.sleep(3)
                
                # Now scan (will see ALL networks)
                result = subprocess.run(
                    ["netsh", "wlan", "show", "networks", "mode=bssid"],
                    capture_output=True, text=True
                )
                
                # Reconnect if we disconnected
                if current_ssid:
                    if self.debug:
                        print(f"[DEBUG] Reconnecting to {current_ssid}...")
                    subprocess.run(
                        ["netsh", "wlan", "connect", f"name={current_ssid}"],
                        capture_output=True, text=True
                    )
                    time.sleep(2)
                
                if result.returncode != 0:
                    return [{"error": "Wi-Fi adapter not found. Make sure Wi-Fi is enabled."}]
                
                networks = self._parse_windows_output(result.stdout)
                
            elif self.os_type == "Linux":
                result = subprocess.run(
                    ["sudo", "iwlist", "scan"],
                    capture_output=True, text=True
                )
                if "Permission denied" in result.stderr or result.returncode != 0:
                    return [{"error": "Run with sudo: sudo python app.py"}]
                networks = self._parse_linux_output(result.stdout)
                
            elif self.os_type == "Darwin":
                result = subprocess.run(
                    ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"],
                    capture_output=True, text=True
                )
                if result.returncode != 0:
                    return [{"error": "Wi-Fi not available. Make sure Wi-Fi is on."}]
                networks = self._parse_mac_output(result.stdout)
            else:
                return [{"error": f"Unsupported OS: {self.os_type}"}]
                
        except Exception as e:
            return [{"error": f"Scan failed: {str(e)}"}]
        
        if self.debug:
            print(f"[DEBUG] Found {len(networks)} networks")
        
        return networks
    
    def _get_current_ssid(self):
        """Get currently connected Wi-Fi SSID"""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if 'SSID' in line and 'BSSID' not in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        ssid = parts[1].strip()
                        if ssid and ssid != '':
                            return ssid
        except:
            pass
        return None
    
    def _normalize_security_label(self, security, encryption=None, auth=None):
        security = (security or '').strip()
        encryption = (encryption or '').strip()
        auth = (auth or '').strip()

        if auth and 'open' in auth.lower():
            if not encryption or encryption.lower() in ['none', 'open', '']:
                return 'Open'

        if encryption:
            enc = encryption.lower()
            if enc in ['none', 'open', '']:
                return 'Open'
            if 'wep' in enc:
                return 'WEP'
            if enc in ['aes', 'ccmp', 'tkip', 'ccmp/tkip', 'aes-ccmp']:
                return 'WPA2'

        if security:
            sec = security.lower()
            if 'wpa3' in sec or 'sae' in sec:
                return 'WPA3'
            if 'wpa2' in sec or '802.11i' in sec or 'wpa2-personal' in sec:
                return 'WPA2'
            if 'wpa' in sec and 'wpa2' not in sec and 'wpa3' not in sec:
                return 'WPA'
            if 'wep' in sec:
                return 'WEP'
            if 'open' in sec or 'none' in sec:
                return 'Open'

        return security or 'Unknown'

    def _is_strong_signal(self, signal):
        if not signal:
            return False
        signal = signal.strip()
        if signal.endswith('%'):
            try:
                return int(signal.rstrip('%')) >= 60
            except ValueError:
                return False
        match = re.search(r'(-?\d+)', signal)
        if match:
            try:
                value = int(match.group(1))
                return value >= -70
            except ValueError:
                return False
        return False

    def _parse_windows_output(self, output):
        """Parse Windows netsh wlan show networks mode=bssid output"""
        networks = []
        current_network = {}
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            # SSID line
            if line.startswith('SSID') and ':' in line and 'BSSID' not in line:
                if current_network and current_network.get('ssid'):
                    current_network['security'] = self._normalize_security_label(
                        current_network.get('security', ''),
                        current_network.get('encryption', ''),
                        current_network.get('auth', '')
                    )
                    networks.append(current_network)
                ssid = line.split(':', 1)[1].strip()
                if ssid:
                    current_network = {
                        'ssid': ssid,
                        'security': 'Unknown',
                        'signal': 'N/A',
                        'encryption': '',
                        'auth': ''
                    }
                else:
                    current_network = {}
            
            # Authentication
            elif 'Authentication' in line and current_network:
                auth = line.split(':', 1)[1].strip()
                current_network['auth'] = auth
                current_network['security'] = self._normalize_security_label(
                    auth,
                    current_network.get('encryption', ''),
                    auth
                )
            
            # Encryption
            elif 'Encryption' in line and current_network:
                encryption = line.split(':', 1)[1].strip()
                current_network['encryption'] = encryption
                current_network['security'] = self._normalize_security_label(
                    current_network.get('security', ''),
                    encryption,
                    current_network.get('auth', '')
                )
            
            # Signal
            elif 'Signal' in line and current_network:
                signal = line.split(':', 1)[1].strip()
                current_network['signal'] = signal + '%'
            
            # Radio type/Band
            elif 'Radio type' in line and current_network:
                current_network['band'] = line.split(':', 1)[1].strip()
        
        # Add last network
        if current_network and current_network.get('ssid'):
            current_network['security'] = self._normalize_security_label(
                current_network.get('security', ''),
                current_network.get('encryption', ''),
                current_network.get('auth', '')
            )
            networks.append(current_network)
        
        # Remove duplicates and normalize security labels
        seen = set()
        unique_networks = []
        for net in networks:
            if net['ssid'] not in seen:
                seen.add(net['ssid'])
                net['security'] = self._normalize_security_label(
                    net.get('security', ''),
                    net.get('encryption', ''),
                    net.get('auth', '')
                )
                unique_networks.append(net)
        
        return unique_networks
    
    def _parse_windows_simple(self, output):
        """Parse Windows netsh wlan show networks (simple) output"""
        networks = []
        current_network = {}
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            if 'SSID' in line and ':' in line:
                if current_network and current_network.get('ssid'):
                    networks.append(current_network)
                ssid = line.split(':', 1)[1].strip()
                if ssid and ssid != '' and ssid != ' ':
                    current_network = {'ssid': ssid, 'security': 'Unknown'}
            
            elif 'Authentication' in line and current_network:
                current_network['security'] = line.split(':', 1)[1].strip()
        
        if current_network and current_network.get('ssid'):
            networks.append(current_network)
        
        return networks
    
    def _parse_linux_output(self, output):
        """Parse Linux iwlist output"""
        networks = []
        cells = output.split('Cell ')
        
        for cell in cells[1:]:
            network = {}
            
            ssid_match = re.search(r'ESSID:"(.+)"', cell)
            if ssid_match and ssid_match.group(1):
                network['ssid'] = ssid_match.group(1)
            else:
                continue
            
            if 'Encryption key:on' in cell:
                if re.search(r'WPA3|SAE', cell, re.I):
                    network['security'] = 'WPA3'
                elif re.search(r'WPA2|802\.11i', cell, re.I):
                    network['security'] = 'WPA2'
                elif re.search(r'WPA', cell, re.I):
                    network['security'] = 'WPA'
                else:
                    network['security'] = 'WEP'
            else:
                network['security'] = 'Open'
            
            signal_match = re.search(r'Signal level=(-?\d+)', cell)
            if signal_match:
                network['signal'] = signal_match.group(1) + ' dBm'
            else:
                network['signal'] = 'N/A'
            
            freq_match = re.search(r'Frequency:(\d+\.\d+)', cell)
            if freq_match:
                network['frequency'] = freq_match.group(1) + ' GHz'
            
            network['security'] = self._normalize_security_label(
                network.get('security', ''),
                None,
                None
            )
            networks.append(network)
        
        return networks
    
    def _parse_mac_output(self, output):
        """Parse Mac airport output"""
        networks = []
        lines = output.split('\n')[1:]
        
        for line in lines:
            if line.strip():
                parts = line.split()
                if len(parts) >= 5:
                    ssid_parts = []
                    security = parts[-3] if len(parts) > 3 else 'Unknown'
                    signal = parts[-2] if len(parts) > 2 else 'N/A'
                    band = parts[-1] if len(parts) > 1 else 'Unknown'
                    
                    for i in range(len(parts) - 3):
                        ssid_parts.append(parts[i])
                    
                    ssid = ' '.join(ssid_parts) if ssid_parts else 'Hidden'
                    
                    network = {
                        'ssid': ssid,
                        'security': self._normalize_security_label(security),
                        'signal': signal,
                        'band': band
                    }
                    networks.append(network)
        
        return networks
    
    def get_encryption_rank(self, security):
        """Rank encryption security level"""
        ranking = {
            'Open': 0,
            'WEP': 1,
            'WPA': 2,
            'WPA2': 3,
            'WPA3': 4
        }
        for key in ranking:
            if key.lower() in security.lower():
                return ranking[key]
        return 0
    
    def identify_rogue_aps(self, networks, trusted_ssids=None):
        """Identify potential rogue access points - AGGRESSIVELY AVOID FALSE POSITIVES"""
        if trusted_ssids is None:
            trusted_ssids = []
        
        # Auto-add current connected network to trusted list
        current_ssid = self._get_current_ssid()
        if current_ssid and current_ssid not in trusted_ssids:
            trusted_ssids.append(current_ssid)
        
        rogue_aps = []
        for network in networks:
            is_rogue = False
            reasons = []
            
            signal_str = network.get('signal', '')
            security = network.get('security', '')
            encryption = network.get('encryption', '')
            auth = network.get('auth', '')
            ssid = network.get('ssid', '')
            ssid_lower = ssid.lower()
            
            security = self._normalize_security_label(security, encryption, auth)
            network['security'] = security
            
            if security in ['WPA3', 'WPA2', 'WPA']:
                continue
            
            if security not in ['Open', 'WEP']:
                continue
            
            # Common home router SSIDs - NOT ROGUE
            safe_patterns = [
                'linksys', 'netgear', 'tp-link', 'asus', 'huawei', 'zyxel', 'dlink', 'belkin',
                'home', 'wifi', '2.4', '5g', 'ext', 'guest', 'private',
                'dna', 'tello', 'il-410td', 'we7b', 'medhat', 'yasser', 'we_',
                'iphone', 'android', 'samsung', 'xiaomi'
            ]
            if any(pattern in ssid_lower for pattern in safe_patterns):
                continue
            
            # Check if it's a trusted network
            is_trusted = False
            for trusted in trusted_ssids:
                if trusted and trusted.lower() == ssid_lower:
                    is_trusted = True
                    break
            
            if not is_trusted:
                if security == 'Open':
                    if self._is_strong_signal(signal_str) and (not encryption or encryption.lower() in ['none', 'open', '']):
                        is_rogue = True
                        reasons.append('Open network with strong signal - possible honeypot')
                elif security == 'WEP':
                    is_rogue = True
                    reasons.append('WEP encryption - deprecated and insecure')
            
            if is_rogue:
                network['rogue_reasons'] = reasons
                rogue_aps.append(network)
        
        return rogue_aps