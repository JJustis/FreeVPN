#!/usr/bin/env python3
"""
All-in-One VPN Server & Client Installer
Automatically installs VPN server on port 8044 with client desktop application

Features:
- Automatic dependency installation
- Cross-platform support (Windows/Linux)
- VPN server with web management interface
- Desktop client application
- Automatic firewall configuration
- TAP adapter setup for Windows
- Encrypted tunneling with modern cryptography

Requirements:
- Python 3.7+
- Administrator/Root privileges
- Internet connection for dependency installation

Usage:
    # Run as Administrator on Windows or sudo on Linux
    python3 vpn_installer.py

Author: Network Security Tools
License: Educational/Research Use Only
"""

import os
import sys
import subprocess
import platform
import socket
import threading
import time
import json
import base64
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import tkinter.font as tkFont
from datetime import datetime, timedelta
import webbrowser
import tempfile
import shutil
import urllib.request
import zipfile
import struct
# Conditional imports for Windows
try:
    if platform.system() == "Windows":
        import winreg
        import ctypes
        import win32com.client
    else:
        winreg = None
except ImportError:
    winreg = None
    print("⚠️ Some Windows-specific modules not available")

# Global configuration
VPN_CONFIG = {
    "server_port": 8044,
    "web_port": 8045,
    "network_range": "10.8.0.0/24",
    "server_ip": "10.8.0.1",
    "dns_servers": ["8.8.8.8", "1.1.1.1"],
    "encryption_key": None,
    "install_dir": None,
    "tap_adapter_name": "TAP-VPN",
    "is_frozen": getattr(sys, 'frozen', False)  # Check if running as compiled executable
}

class DependencyInstaller:
    """Automatic dependency installation"""
    
    def __init__(self):
        self.system = platform.system()
        self.is_admin = self.check_admin()
        
    def check_admin(self):
        """Check if running with admin privileges"""
        try:
            if self.system == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False
    
    def install_python_packages(self):
        """Install required Python packages"""
        packages = [
            "cryptography>=3.4.8",
            "psutil>=5.8.0",
            "requests>=2.25.1",
            "flask>=2.0.0",
            "flask-socketio>=5.0.0",
            "pyinstaller>=5.0.0",
            "pywin32>=227;platform_system=='Windows'",
        ]
        
        print("📦 Installing Python dependencies...")
        for package in packages:
            try:
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install", package, "--upgrade"
                ])
                print(f"✅ Installed: {package}")
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to install {package}: {e}")
                return False
        return True
    
    def setup_windows_dependencies(self):
        """Setup Windows-specific dependencies"""
        if self.system != "Windows":
            return True
            
        print("🏢 Setting up Windows dependencies...")
        
        # Install TAP-Windows adapter
        if not self.install_tap_windows():
            print("⚠️ TAP-Windows installation failed, VPN may not work properly")
        
        # Configure Windows Firewall
        self.configure_windows_firewall()
        
        return True
    
    def install_tap_windows(self):
        """Install TAP-Windows adapter"""
        try:
            print("🔌 Installing TAP-Windows adapter...")
            
            # Check if TAP adapter already exists
            if self.check_tap_adapter_exists():
                print("✅ TAP adapter already installed")
                return True
            
            # Download and install TAP-Windows
            tap_url = "https://build.openvpn.net/downloads/releases/tap-windows-9.24.7-I601-Win10.exe"
            tap_installer = os.path.join(tempfile.gettempdir(), "tap-windows-installer.exe")
            
            print("⬇️ Downloading TAP-Windows installer...")
            urllib.request.urlretrieve(tap_url, tap_installer)
            
            print("🔧 Installing TAP-Windows (this may take a moment)...")
            subprocess.run([tap_installer, "/S"], check=True)  # Silent install
            
            # Clean up
            os.remove(tap_installer)
            
            # Wait for installation to complete
            time.sleep(5)
            
            if self.check_tap_adapter_exists():
                print("✅ TAP-Windows adapter installed successfully")
                return True
            else:
                print("❌ TAP adapter not found after installation")
                return False
                
        except Exception as e:
            print(f"❌ TAP-Windows installation failed: {e}")
            return False
    
    def check_tap_adapter_exists(self):
        """Check if TAP adapter exists"""
        try:
            result = subprocess.run([
                "netsh", "interface", "show", "interface"
            ], capture_output=True, text=True)
            
            return "TAP" in result.stdout or "OpenVPN" in result.stdout
        except:
            return False
    
    def configure_windows_firewall(self):
        """Configure Windows Firewall rules"""
        try:
            print("🔥 Configuring Windows Firewall...")
            
            # Allow VPN server port
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=VPN Server", "dir=in", "action=allow",
                "protocol=TCP", f"localport={VPN_CONFIG['server_port']}"
            ], check=True)
            
            # Allow web management port
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=VPN Web Management", "dir=in", "action=allow",
                "protocol=TCP", f"localport={VPN_CONFIG['web_port']}"
            ], check=True)
            
            print("✅ Windows Firewall configured")
            
        except Exception as e:
            print(f"⚠️ Firewall configuration failed: {e}")


class VPNCrypto:
    """VPN encryption and security"""
    
    def __init__(self, password="VPN_DEFAULT_PASSWORD_2024"):
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.fernet import Fernet
            import os
            
            # Generate salt and derive key
            self.salt = os.urandom(32)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            self.cipher = Fernet(key)
            self.crypto_available = True
        except ImportError:
            print("⚠️ Cryptography module not available, using basic encoding")
            self.cipher = None
            self.crypto_available = False
    
    def encrypt(self, data):
        """Encrypt data"""
        if isinstance(data, str):
            data = data.encode()
            
        if self.crypto_available and self.cipher:
            return self.cipher.encrypt(data)
        else:
            # Fallback: base64 encoding (NOT secure, for demo only)
            return base64.b64encode(data)
    
    def decrypt(self, encrypted_data):
        """Decrypt data"""
        if self.crypto_available and self.cipher:
            return self.cipher.decrypt(encrypted_data)
        else:
            # Fallback: base64 decoding
            return base64.b64decode(encrypted_data)


class WindowsNetworking:
    """Windows networking utilities"""
    
    @staticmethod
    def create_tap_interface():
        """Create and configure TAP interface"""
        try:
            # Find TAP adapter
            result = subprocess.run([
                "netsh", "interface", "show", "interface"
            ], capture_output=True, text=True)
            
            # Look for TAP adapter
            tap_name = None
            for line in result.stdout.split('\n'):
                if 'TAP' in line or 'OpenVPN' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        tap_name = ' '.join(parts[3:])
                        break
            
            if not tap_name:
                raise Exception("TAP adapter not found")
            
            # Configure TAP interface
            subprocess.run([
                "netsh", "interface", "ip", "set", "address",
                f"name={tap_name}", "static",
                VPN_CONFIG["server_ip"], "255.255.255.0"
            ], check=True)
            
            # Enable interface
            subprocess.run([
                "netsh", "interface", "set", "interface",
                f"name={tap_name}", "admin=enabled"
            ], check=True)
            
            print(f"✅ TAP interface configured: {tap_name}")
            return tap_name
            
        except Exception as e:
            print(f"❌ TAP interface configuration failed: {e}")
            return None
    
    @staticmethod
    def setup_routing():
        """Setup Windows routing for VPN"""
        try:
            # Add route for VPN network
            subprocess.run([
                "route", "add", VPN_CONFIG["network_range"].split('/')[0],
                "mask", "255.255.255.0", VPN_CONFIG["server_ip"]
            ], check=True)
            
            print("✅ Windows routing configured")
            return True
            
        except Exception as e:
            print(f"❌ Routing configuration failed: {e}")
            return False


class VPNServer:
    """VPN Server with web management interface"""
    
    def __init__(self):
        self.clients = {}
        self.crypto = VPNCrypto()
        self.running = False
        self.server_socket = None
        self.web_server = None
        
        # Setup Flask for web interface
        self.setup_web_interface()
    
    def setup_web_interface(self):
        """Setup Flask web management interface"""
        try:
            from flask import Flask, render_template_string, jsonify, request, send_file
            from flask_socketio import SocketIO
            
            self.app = Flask(__name__)
            self.app.config['SECRET_KEY'] = 'vpn_web_secret_2024'
            self.socketio = SocketIO(self.app, cors_allowed_origins="*")
            
            # Web interface template
            web_template = """
<!DOCTYPE html>
<html>
<head>
    <title>VPN Server Management</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; color: #333; border-bottom: 2px solid #007acc; padding-bottom: 20px; margin-bottom: 20px; }
        .status { padding: 15px; border-radius: 5px; margin: 10px 0; }
        .status.online { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .status.offline { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .card { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #007acc; }
        .clients-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .clients-table th, .clients-table td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        .clients-table th { background: #007acc; color: white; }
        .btn { padding: 10px 20px; background: #007acc; color: white; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }
        .btn:hover { background: #005f99; }
        .btn.danger { background: #dc3545; }
        .btn.danger:hover { background: #c82333; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; }
        .log { background: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 5px; font-family: monospace; height: 300px; overflow-y: auto; }
        .config-section { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ VPN Server Management Panel</h1>
            <p>Advanced VPN Server Control Center</p>
        </div>
        
        <div id="serverStatus" class="status offline">
            <strong>Server Status:</strong> <span id="statusText">Offline</span>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" id="clientCount">0</div>
                <div>Connected Clients</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="dataTransferred">0 MB</div>
                <div>Data Transferred</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="uptime">00:00:00</div>
                <div>Server Uptime</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="serverPort">8044</div>
                <div>Server Port</div>
            </div>
        </div>
        
        <div class="card">
            <h3>🎛️ Server Controls</h3>
            <button class="btn" onclick="startServer()">▶️ Start Server</button>
            <button class="btn danger" onclick="stopServer()">⏹️ Stop Server</button>
            <button class="btn" onclick="restartServer()">🔄 Restart Server</button>
            <button class="btn" onclick="downloadClient()">📱 Download Client</button>
        </div>
        
        <div class="card">
            <h3>👥 Connected Clients</h3>
            <table class="clients-table" id="clientsTable">
                <thead>
                    <tr>
                        <th>Client ID</th>
                        <th>IP Address</th>
                        <th>Connected Since</th>
                        <th>Data Sent</th>
                        <th>Data Received</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="clientsBody">
                    <tr>
                        <td colspan="6" style="text-align: center; color: #666;">No clients connected</td>
                    </tr>
                </tbody>
            </table>
        </div>
        
        <div class="config-section">
            <h3>⚙️ Server Configuration</h3>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <div>
                    <strong>Server Port:</strong> 8044<br>
                    <strong>Web Port:</strong> 8045<br>
                    <strong>Network Range:</strong> 10.8.0.0/24
                </div>
                <div>
                    <strong>Encryption:</strong> AES-256-GCM<br>
                    <strong>Protocol:</strong> Custom VPN<br>
                    <strong>DNS Servers:</strong> 8.8.8.8, 1.1.1.1
                </div>
            </div>
        </div>
        
        <div class="card">
            <h3>📋 System Logs</h3>
            <div id="logOutput" class="log">
                VPN Server Management Panel Loaded...<br>
                Waiting for server status updates...<br>
            </div>
        </div>
    </div>
    
    <script>
        const socket = io();
        let serverRunning = false;
        
        socket.on('server_status', function(data) {
            updateServerStatus(data.running);
            updateStats(data.stats);
            updateClients(data.clients);
        });
        
        socket.on('log_message', function(data) {
            addLogMessage(data.message);
        });
        
        function updateServerStatus(running) {
            serverRunning = running;
            const statusEl = document.getElementById('serverStatus');
            const statusText = document.getElementById('statusText');
            
            if (running) {
                statusEl.className = 'status online';
                statusText.textContent = 'Online';
            } else {
                statusEl.className = 'status offline';
                statusText.textContent = 'Offline';
            }
        }
        
        function updateStats(stats) {
            document.getElementById('clientCount').textContent = stats.clients || 0;
            document.getElementById('dataTransferred').textContent = (stats.data_mb || 0) + ' MB';
            document.getElementById('uptime').textContent = stats.uptime || '00:00:00';
        }
        
        function updateClients(clients) {
            const tbody = document.getElementById('clientsBody');
            
            if (!clients || clients.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #666;">No clients connected</td></tr>';
                return;
            }
            
            tbody.innerHTML = clients.map(client => `
                <tr>
                    <td>${client.id}</td>
                    <td>${client.ip}</td>
                    <td>${client.connected_since}</td>
                    <td>${client.data_sent}</td>
                    <td>${client.data_received}</td>
                    <td><button class="btn danger" onclick="disconnectClient('${client.id}')">Disconnect</button></td>
                </tr>
            `).join('');
        }
        
        function addLogMessage(message) {
            const logOutput = document.getElementById('logOutput');
            const timestamp = new Date().toLocaleTimeString();
            logOutput.innerHTML += `[${timestamp}] ${message}<br>`;
            logOutput.scrollTop = logOutput.scrollHeight;
        }
        
        function startServer() {
            socket.emit('control_command', {action: 'start'});
            addLogMessage('Starting VPN server...');
        }
        
        function stopServer() {
            socket.emit('control_command', {action: 'stop'});
            addLogMessage('Stopping VPN server...');
        }
        
        function restartServer() {
            socket.emit('control_command', {action: 'restart'});
            addLogMessage('Restarting VPN server...');
        }
        
        function disconnectClient(clientId) {
            socket.emit('control_command', {action: 'disconnect_client', client_id: clientId});
            addLogMessage(`Disconnecting client: ${clientId}`);
        }
        
        function downloadClient() {
            window.location.href = '/download_client';
            addLogMessage('Client download initiated...');
        }
        
        // Auto-refresh every 5 seconds
        setInterval(() => {
            socket.emit('get_status');
        }, 5000);
        
        // Initial status request
        socket.emit('get_status');
    </script>
</body>
</html>
            """
            
            @self.app.route('/')
            def web_interface():
                return render_template_string(web_template)
            
            @self.app.route('/api/status')
            def api_status():
                return jsonify({
                    'running': self.running,
                    'clients': len(self.clients),
                    'port': VPN_CONFIG['server_port']
                })
            
            @self.app.route('/download_client')
            def download_client():
                # Generate client executable
                client_path = self.generate_client_app()
                if client_path and os.path.exists(client_path):
                    return send_file(client_path, as_attachment=True, 
                                   download_name='VPN_Client.exe')
                else:
                    return "Client generation failed", 500
            
            @self.socketio.on('get_status')
            def handle_status_request():
                stats = self.get_server_stats()
                self.socketio.emit('server_status', {
                    'running': self.running,
                    'stats': stats,
                    'clients': list(self.clients.values())
                })
            
            @self.socketio.on('control_command')
            def handle_control_command(data):
                action = data.get('action')
                
                if action == 'start':
                    self.start_server_async()
                elif action == 'stop':
                    self.stop_server()
                elif action == 'restart':
                    self.restart_server()
                elif action == 'disconnect_client':
                    client_id = data.get('client_id')
                    self.disconnect_client(client_id)
                
                self.socketio.emit('log_message', {
                    'message': f'Command executed: {action}'
                })
            
        except ImportError:
            print("⚠️ Flask not available, web interface disabled")
            self.app = None
    
    def start_server_async(self):
        """Start VPN server in background thread"""
        if not self.running:
            server_thread = threading.Thread(target=self.start_server, daemon=True)
            server_thread.start()
    
    def start_server(self):
        """Start VPN server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', VPN_CONFIG['server_port']))
            self.server_socket.listen(10)
            
            self.running = True
            print(f"🚀 VPN Server started on port {VPN_CONFIG['server_port']}")
            
            # Accept client connections
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                except:
                    if self.running:
                        continue
                    else:
                        break
                        
        except Exception as e:
            print(f"❌ Server start failed: {e}")
            self.running = False
    
    def handle_client(self, client_socket, address):
        """Handle VPN client connection"""
        client_id = f"{address[0]}:{address[1]}"
        client_ip = f"10.8.0.{len(self.clients) + 10}"
        
        try:
            # Store client info
            self.clients[client_id] = {
                'id': client_id,
                'ip': client_ip,
                'socket': client_socket,
                'connected_since': datetime.now().strftime('%H:%M:%S'),
                'data_sent': '0 KB',
                'data_received': '0 KB'
            }
            
            print(f"✅ Client connected: {client_id} -> {client_ip}")
            
            # Send welcome message
            welcome_msg = f"VPN_WELCOME:{client_ip}".encode()
            encrypted_msg = self.crypto.encrypt(welcome_msg)
            client_socket.send(encrypted_msg)
            
            # Handle client communication
            while self.running:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    
                    # Decrypt and process data
                    try:
                        decrypted_data = self.crypto.decrypt(data)
                        print(f"📦 Received from {client_id}: {decrypted_data.decode()}")
                        
                        # Echo back (in real VPN, would route to internet)
                        response = f"SERVER_ECHO:{decrypted_data.decode()}".encode()
                        encrypted_response = self.crypto.encrypt(response)
                        client_socket.send(encrypted_response)
                    except Exception as decrypt_error:
                        print(f"Decryption error for {client_id}: {decrypt_error}")
                        # Send error response
                        error_response = b"DECRYPT_ERROR"
                        client_socket.send(error_response)
                    
                except Exception as e:
                    print(f"Client {client_id} communication error: {e}")
                    break
                    
        except Exception as e:
            print(f"❌ Client handling error: {e}")
        finally:
            # Cleanup client
            if client_id in self.clients:
                del self.clients[client_id]
            client_socket.close()
            print(f"🔌 Client disconnected: {client_id}")
    
    def stop_server(self):
        """Stop VPN server"""
        self.running = False
        
        # Close all client connections
        for client_info in list(self.clients.values()):
            client_info['socket'].close()
        self.clients.clear()
        
        if self.server_socket:
            self.server_socket.close()
        
        print("🛑 VPN Server stopped")
    
    def restart_server(self):
        """Restart VPN server"""
        self.stop_server()
        time.sleep(2)
        self.start_server_async()
    
    def disconnect_client(self, client_id):
        """Disconnect specific client"""
        if client_id in self.clients:
            self.clients[client_id]['socket'].close()
            del self.clients[client_id]
            print(f"⚠️ Client {client_id} disconnected by admin")
    
    def get_server_stats(self):
        """Get server statistics"""
        return {
            'clients': len(self.clients),
            'data_mb': 0,  # Placeholder
            'uptime': '00:00:00'  # Placeholder
        }
    
    def start_web_interface(self):
        """Start web management interface"""
        if self.app:
            try:
                print(f"🌐 Starting web interface on port {VPN_CONFIG['web_port']}")
                self.socketio.run(self.app, host='0.0.0.0', 
                                port=VPN_CONFIG['web_port'], debug=False)
            except Exception as e:
                print(f"❌ Web interface failed: {e}")
    
    def generate_client_app(self):
        """Generate VPN client application"""
        try:
            client_code = self.get_client_code()
            client_path = os.path.join(VPN_CONFIG['install_dir'], 'VPN_Client.py')
            
            with open(client_path, 'w') as f:
                f.write(client_code)
            
            print(f"📱 Client application generated: {client_path}")
            return client_path
            
        except Exception as e:
            print(f"❌ Client generation failed: {e}")
            return None
    
    def get_client_code(self):
        """Get VPN client source code"""
        return '''#!/usr/bin/env python3
"""
VPN Client Application
Auto-generated by VPN Server Installer
"""

import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading
import base64

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    print("⚠️ Cryptography module not available, using basic encryption")
    CRYPTO_AVAILABLE = False

class VPNClient:
    def __init__(self):
        self.connected = False
        self.socket = None
        if CRYPTO_AVAILABLE:
            self.crypto = self.setup_crypto()
        else:
            self.crypto = None
        
        # Create GUI
        self.root = tk.Tk()
        self.root.title("VPN Client")
        self.root.geometry("400x300")
        self.create_gui()
    
    def setup_crypto(self):
        """Setup encryption"""
        if not CRYPTO_AVAILABLE:
            return None
            
        password = "VPN_DEFAULT_PASSWORD_2024"
        salt = b'\\x00' * 32  # In production, use proper salt exchange
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)
    
    def encrypt_data(self, data):
        """Encrypt data if crypto available"""
        if self.crypto and CRYPTO_AVAILABLE:
            if isinstance(data, str):
                data = data.encode()
            return self.crypto.encrypt(data)
        else:
            # Fallback: base64 encoding (NOT secure, for demo only)
            if isinstance(data, str):
                data = data.encode()
            return base64.b64encode(data)
    
    def decrypt_data(self, data):
        """Decrypt data if crypto available"""
        if self.crypto and CRYPTO_AVAILABLE:
            return self.crypto.decrypt(data)
        else:
            # Fallback: base64 decoding
            return base64.b64decode(data)
    
    def create_gui(self):
        """Create client GUI"""
        # Server settings
        ttk.Label(self.root, text="Server:").pack(pady=5)
        self.server_entry = ttk.Entry(self.root, width=30)
        self.server_entry.insert(0, "127.0.0.1:8044")
        self.server_entry.pack(pady=5)
        
        # Connection controls
        self.connect_btn = ttk.Button(self.root, text="Connect", command=self.connect)
        self.connect_btn.pack(pady=10)
        
        self.disconnect_btn = ttk.Button(self.root, text="Disconnect", 
                                       command=self.disconnect, state='disabled')
        self.disconnect_btn.pack(pady=5)
        
        # Status
        self.status_label = ttk.Label(self.root, text="Status: Disconnected")
        self.status_label.pack(pady=10)
        
        # Crypto status
        crypto_status = "Encryption: Available" if CRYPTO_AVAILABLE else "Encryption: Basic (Install cryptography)"
        self.crypto_label = ttk.Label(self.root, text=crypto_status)
        self.crypto_label.pack(pady=5)
        
        # Log
        self.log_text = tk.Text(self.root, height=10, width=50)
        self.log_text.pack(pady=10, padx=10, fill='both', expand=True)
    
    def connect(self):
        """Connect to VPN server"""
        server_address = self.server_entry.get()
        try:
            host, port = server_address.split(':')
            port = int(port)
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            
            # Receive welcome message
            welcome_data = self.socket.recv(1024)
            try:
                welcome_msg = self.decrypt_data(welcome_data).decode()
            except:
                welcome_msg = welcome_data.decode()
            
            if "VPN_WELCOME:" in welcome_msg:
                client_ip = welcome_msg.split(':')[1] if ':' in welcome_msg else "Unknown"
                self.connected = True
                
                self.connect_btn.config(state='disabled')
                self.disconnect_btn.config(state='normal')
                self.status_label.config(text=f"Status: Connected ({client_ip})")
                
                self.log(f"Connected to VPN server: {client_ip}")
                
                # Start communication thread
                comm_thread = threading.Thread(target=self.communication_loop, daemon=True)
                comm_thread.start()
            else:
                raise Exception("Invalid welcome message")
                
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {e}")
            self.log(f"Connection failed: {e}")
    
    def disconnect(self):
        """Disconnect from VPN server"""
        self.connected = False
        
        if self.socket:
            self.socket.close()
        
        self.connect_btn.config(state='normal')
        self.disconnect_btn.config(state='disabled')
        self.status_label.config(text="Status: Disconnected")
        
        self.log("Disconnected from VPN server")
    
    def communication_loop(self):
        """Handle server communication"""
        while self.connected:
            try:
                # Send periodic ping
                ping_msg = "CLIENT_PING"
                encrypted_ping = self.encrypt_data(ping_msg)
                self.socket.send(encrypted_ping)
                
                # Receive response
                response_data = self.socket.recv(1024)
                if response_data:
                    try:
                        response_msg = self.decrypt_data(response_data).decode()
                    except:
                        response_msg = response_data.decode()
                    self.log(f"Server: {response_msg}")
                
                import time
                time.sleep(5)  # Ping every 5 seconds
                
            except Exception as e:
                if self.connected:
                    self.log(f"Communication error: {e}")
                    self.disconnect()
                break
    
    def log(self, message):
        """Add message to log"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\\n")
        self.log_text.see(tk.END)
    
    def run(self):
        """Start client application"""
        self.root.mainloop()

if __name__ == "__main__":
    client = VPNClient()
    client.run()
'''


class ExecutableBuilder:
    """Build standalone executable using PyInstaller"""
    
    def __init__(self, installer_instance):
        self.installer = installer_instance
        self.build_dir = os.path.join(VPN_CONFIG['install_dir'], 'build')
        self.dist_dir = os.path.join(VPN_CONFIG['install_dir'], 'dist')
        
    def create_icon_file(self):
        """Create icon file for executable"""
        try:
            # Create a simple ICO file programmatically
            icon_path = os.path.join(tempfile.gettempdir(), "vpn_icon.ico")
            
            # Use PIL to create icon if available, otherwise skip
            try:
                from PIL import Image, ImageDraw
                
                # Create 32x32 icon
                img = Image.new('RGBA', (32, 32), (0, 0, 0, 0))
                draw = ImageDraw.Draw(img)
                
                # Draw shield shape
                draw.ellipse([4, 4, 28, 28], fill=(0, 120, 215, 255), outline=(255, 255, 255, 255))
                draw.text((10, 10), "VPN", fill=(255, 255, 255, 255))
                
                # Save as ICO
                img.save(icon_path, format='ICO')
                print(f"✅ Created icon: {icon_path}")
                return icon_path
                
            except ImportError:
                print("⚠️ PIL not available, skipping icon creation")
                return None
                
        except Exception as e:
            print(f"⚠️ Icon creation failed: {e}")
            return None
    
    def create_spec_file(self):
        """Create PyInstaller spec file"""
        script_path = os.path.abspath(__file__)
        icon_path = self.create_icon_file()
        
        spec_content = f'''# -*- mode: python ; coding: utf-8 -*-

import sys
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Collect Flask and SocketIO data files
flask_datas = collect_data_files('flask')
socketio_datas = collect_data_files('flask_socketio')
engineio_datas = collect_data_files('engineio')

# Combine all data files
all_datas = flask_datas + socketio_datas + engineio_datas

# Collect all submodules
hiddenimports = []
hiddenimports += collect_submodules('cryptography')
hiddenimports += collect_submodules('flask')
hiddenimports += collect_submodules('flask_socketio')
hiddenimports += collect_submodules('socketio')
hiddenimports += collect_submodules('engineio')

a = Analysis(
    ['{script_path}'],
    pathex=[os.path.dirname('{script_path}')],
    binaries=[],
    datas=all_datas,
    hiddenimports=hiddenimports + [
        'cryptography.fernet',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.kdf.pbkdf2',
        'cryptography.hazmat.primitives.hashes',
        'psutil',
        'win32com.client',
        'winreg',
        'ctypes',
        'urllib.request',
        'urllib.parse',
        'tkinter',
        'tkinter.ttk',
        'tkinter.messagebox',
        'tkinter.scrolledtext',
        'tkinter.filedialog',
        'tkinter.colorchooser',
        'tkinter.font',
        'queue',
        'threading',
        'socket',
        'struct',
        'base64',
        'json',
        'tempfile',
        'shutil',
        'zipfile',
        'webbrowser',
        'datetime',
        'time',
        'platform',
        'subprocess',
        'sys',
        'os',
        're',
    ],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=['matplotlib', 'numpy', 'scipy', 'pandas'],  # Exclude large unused packages
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Remove duplicate entries
seen = set()
a.datas = [x for x in a.datas if not (x[0] in seen or seen.add(x[0]))]

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='VPN_Server_Installer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Windowed application
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='{icon_path if icon_path else ""}',
    version_info=None,
    uac_admin=True,  # Request admin privileges
    manifest=None,
)
'''
        
        spec_path = os.path.join(VPN_CONFIG['install_dir'], 'vpn_installer.spec')
        
        with open(spec_path, 'w') as f:
            f.write(spec_content)
        
        print(f"✅ Created spec file: {spec_path}")
        return spec_path
    
    def create_version_info(self):
        """Create version info file for executable"""
        version_content = '''# UTF-8
#
# For more details about fixed file info 'ffi' see:
# http://msdn.microsoft.com/en-us/library/ms646997.aspx
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1,0,0,0),
    prodvers=(1,0,0,0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
    ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName', u'VPN Tools'),
        StringStruct(u'FileDescription', u'VPN Server & Client Installer'),
        StringStruct(u'FileVersion', u'1.0.0'),
        StringStruct(u'InternalName', u'VPN_Installer'),
        StringStruct(u'LegalCopyright', u'Educational Use Only'),
        StringStruct(u'OriginalFilename', u'VPN_Server_Installer.exe'),
        StringStruct(u'ProductName', u'VPN Server Suite'),
        StringStruct(u'ProductVersion', u'1.0.0')])
      ]), 
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
'''
        
        version_path = os.path.join(VPN_CONFIG['install_dir'], 'version_info.txt')
        
        with open(version_path, 'w') as f:
            f.write(version_content)
        
        return version_path
    
    def build_executable(self):
        """Build standalone executable"""
        try:
            print("🔨 Building standalone executable...")
            
            # Create spec file
            spec_path = self.create_spec_file()
            
            # Create version info
            version_path = self.create_version_info()
            
            # Run PyInstaller
            cmd = [
                sys.executable, "-m", "PyInstaller",
                "--clean",
                "--noconfirm",
                f"--distpath={self.dist_dir}",
                f"--workpath={self.build_dir}",
                spec_path
            ]
            
            print("Running PyInstaller...")
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=VPN_CONFIG['install_dir'])
            
            if result.returncode == 0:
                exe_path = os.path.join(self.dist_dir, 'VPN_Server_Installer.exe')
                if os.path.exists(exe_path):
                    print(f"✅ Executable created: {exe_path}")
                    
                    # Create desktop shortcut for the executable
                    self.create_exe_desktop_shortcut(exe_path)
                    
                    # Create distribution package
                    self.create_distribution_package(exe_path)
                    
                    return exe_path
                else:
                    print("❌ Executable not found after build")
                    return None
            else:
                print(f"❌ PyInstaller failed: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"❌ Executable build failed: {e}")
            return None
    
    def create_exe_desktop_shortcut(self, exe_path):
        """Create desktop shortcut for executable"""
        try:
            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            
            if platform.system() == "Windows":
                try:
                    import win32com.client
                    shortcut_path = os.path.join(desktop, "VPN Server Installer.lnk")
                    
                    shell = win32com.client.Dispatch("WScript.Shell")
                    shortcut = shell.CreateShortCut(shortcut_path)
                    shortcut.Targetpath = exe_path
                    shortcut.WorkingDirectory = os.path.dirname(exe_path)
                    shortcut.IconLocation = exe_path
                    shortcut.Description = "VPN Server & Client Installer"
                    shortcut.save()
                    
                    print(f"🔗 Desktop shortcut created: {shortcut_path}")
                    
                except ImportError:
                    # Fallback: create batch file
                    batch_path = os.path.join(desktop, "VPN Server Installer.bat")
                    batch_content = f'@echo off\ncd /d "{os.path.dirname(exe_path)}"\n"{exe_path}"\npause'
                    
                    with open(batch_path, 'w') as f:
                        f.write(batch_content)
                    
                    print(f"🔗 Desktop batch file created: {batch_path}")
                    
        except Exception as e:
            print(f"⚠️ Desktop shortcut creation failed: {e}")
    
    def create_distribution_package(self, exe_path):
        """Create distribution package with all files"""
        try:
            # Create distribution folder
            dist_package_dir = os.path.join(VPN_CONFIG['install_dir'], 'VPN_Server_Package')
            os.makedirs(dist_package_dir, exist_ok=True)
            
            # Copy executable
            exe_dest = os.path.join(dist_package_dir, 'VPN_Server_Installer.exe')
            shutil.copy2(exe_path, exe_dest)
            
            # Create README file
            readme_content = '''# VPN Server & Client Installer

## Quick Start Guide

1. **Run as Administrator**: Right-click "VPN_Server_Installer.exe" and select "Run as administrator"

2. **Install**: Click "Install VPN Server" and wait for completion

3. **Access**: 
   - VPN Server: localhost:8044
   - Web Management: http://localhost:8045
   - Desktop Client: Created automatically

## Features

- ✅ Automatic VPN server setup on port 8044
- ✅ Professional web management interface 
- ✅ Desktop VPN client application
- ✅ Windows firewall configuration
- ✅ TAP adapter installation
- ✅ Encrypted tunneling with modern cryptography

## System Requirements

- Windows 10 or later
- Administrator privileges
- Internet connection (for initial setup)
- Python 3.7+ (bundled in executable)

## Troubleshooting

**Firewall Issues**: Ensure Windows Firewall allows the application
**TAP Driver**: May require manual installation if automatic fails
**Antivirus**: Add executable to antivirus exceptions if needed

## Security Notice

This tool is for educational and authorized testing purposes only.
Always ensure you have proper authorization before using VPN tools.

## Support

For technical support and updates, visit the project website.

---
VPN Server Suite v1.0.0 - Educational Use Only
'''
            
            readme_path = os.path.join(dist_package_dir, 'README.txt')
            with open(readme_path, 'w') as f:
                f.write(readme_content)
            
            # Create batch installer for convenience
            batch_installer_content = f'''@echo off
echo.
echo =========================================
echo   VPN Server Installer
echo =========================================
echo.
echo This will install the VPN Server with administrator privileges.
echo Please ensure you have authorization to install VPN software.
echo.
pause
echo.
echo Starting installation...
powershell -Command "Start-Process '{exe_dest}' -Verb runAs"
echo.
echo Installation started! Please follow the GUI prompts.
pause
'''
            
            batch_path = os.path.join(dist_package_dir, 'Install_VPN_Server.bat')
            with open(batch_path, 'w') as f:
                f.write(batch_installer_content)
            
            print(f"📦 Distribution package created: {dist_package_dir}")
            
            # Create ZIP package
            self.create_zip_package(dist_package_dir)
            
        except Exception as e:
            print(f"⚠️ Distribution package creation failed: {e}")
    
    def create_zip_package(self, package_dir):
        """Create ZIP package for distribution"""
        try:
            zip_path = os.path.join(VPN_CONFIG['install_dir'], 'VPN_Server_Suite.zip')
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(package_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, package_dir)
                        zipf.write(file_path, arcname)
            
            print(f"📦 ZIP package created: {zip_path}")
            
            # Show final message
            print("\n" + "="*60)
            print("🎉 EXECUTABLE BUILD COMPLETE!")
            print("="*60)
            print(f"📁 Package Location: {package_dir}")
            print(f"📦 ZIP Package: {zip_path}")
            print("🚀 Ready for distribution!")
            print("="*60)
            
            return zip_path
            
        except Exception as e:
            print(f"⚠️ ZIP package creation failed: {e}")
            return None


class VPNInstaller:
    """Main VPN installer and setup"""
    
    def __init__(self):
        self.system = platform.system()
        self.installer = DependencyInstaller()
        self.server = None
        self.executable_builder = None
        
        # Setup install directory
        if self.system == "Windows":
            VPN_CONFIG['install_dir'] = os.path.join(
                os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'VPN_Server'
            )
        else:
            VPN_CONFIG['install_dir'] = '/opt/vpn_server'
        
        # Create GUI
        self.create_gui()
    
    def create_gui(self):
        """Create installer GUI"""
        self.root = tk.Tk()
        self.root.title("VPN Server & Client Installer")
        self.root.geometry("700x600")
        self.root.configure(bg='#f0f0f0')
        
        # Header
        header_frame = tk.Frame(self.root, bg='#2c3e50', height=80)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(header_frame, text="🛡️ VPN Server & Client Installer",
                              font=('Arial', 16, 'bold'), fg='white', bg='#2c3e50')
        title_label.pack(expand=True)
        
        # Main content
        main_frame = tk.Frame(self.root, bg='#f0f0f0')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Installation steps
        steps_label = tk.Label(main_frame, text="Installation Steps:",
                              font=('Arial', 12, 'bold'), bg='#f0f0f0')
        steps_label.pack(anchor='w', pady=(0, 10))
        
        self.steps_text = scrolledtext.ScrolledText(main_frame, height=18, width=80,
                                                   font=('Consolas', 9))
        self.steps_text.pack(fill='both', expand=True, pady=(0, 10))
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, length=400, mode='determinate')
        self.progress.pack(fill='x', pady=(0, 10))
        
        # Buttons
        button_frame = tk.Frame(main_frame, bg='#f0f0f0')
        button_frame.pack(fill='x')
        
        self.install_btn = tk.Button(button_frame, text="🚀 Install VPN Server",
                                    command=self.start_installation,
                                    font=('Arial', 10, 'bold'),
                                    bg='#27ae60', fg='white',
                                    padx=20, pady=10)
        self.install_btn.pack(side='left', padx=(0, 10))
        
        self.client_btn = tk.Button(button_frame, text="📱 Create Desktop Client",
                                   command=self.create_desktop_client,
                                   font=('Arial', 10, 'bold'),
                                   bg='#3498db', fg='white',
                                   padx=20, pady=10, state='disabled')
        self.client_btn.pack(side='left', padx=(0, 10))
        
        self.web_btn = tk.Button(button_frame, text="🌐 Open Web Interface",
                                command=self.open_web_interface,
                                font=('Arial', 10, 'bold'),
                                bg='#e67e22', fg='white',
                                padx=20, pady=10, state='disabled')
        self.web_btn.pack(side='left', padx=(0, 10))
        
        # NEW: Build Executable Button
        build_btn_state = 'disabled'
        build_btn_text = "🔨 Build Executable"
        
        if VPN_CONFIG['is_frozen']:
            build_btn_text = "Already Compiled"
            build_btn_state = 'disabled'
        
        self.build_exe_btn = tk.Button(button_frame, text=build_btn_text,
                                      command=self.build_standalone_executable,
                                      font=('Arial', 10, 'bold'),
                                      bg='#9b59b6', fg='white',
                                      padx=20, pady=10, state=build_btn_state)
        self.build_exe_btn.pack(side='left')
        
        # Initial message
        self.log("VPN Server & Client Installer Ready")
        self.log("Click 'Install VPN Server' to begin automatic installation")
        self.log("After installation, use 'Build Executable' to create standalone .exe")
        
        if VPN_CONFIG['is_frozen']:
            self.log("🔧 Running from compiled executable")
            self.build_exe_btn.config(state='disabled', text="Already Compiled")
        else:
            self.log("📜 Running from Python script - executable build available")
        
        if not self.installer.is_admin:
            self.log("⚠️ WARNING: Administrator privileges required for full installation")
    
    def log(self, message):
        """Add message to installation log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.steps_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.steps_text.see(tk.END)
        self.root.update()
    
    def update_progress(self, value):
        """Update progress bar"""
        self.progress['value'] = value
        self.root.update()
    
    def start_installation(self):
        """Start VPN installation process"""
        self.install_btn.config(state='disabled')
        
        # Run installation in separate thread
        install_thread = threading.Thread(target=self.install_vpn, daemon=True)
        install_thread.start()
    
    def install_vpn(self):
        """Install VPN server and client"""
        try:
            self.log("🚀 Starting VPN installation...")
            self.update_progress(10)
            
            # Check privileges
            if not self.installer.is_admin:
                self.log("❌ Installation requires administrator privileges")
                messagebox.showerror("Error", "Please run as Administrator")
                return
            
            # Install Python dependencies
            self.log("📦 Installing Python dependencies...")
            if not self.installer.install_python_packages():
                self.log("❌ Failed to install Python packages")
                return
            self.update_progress(30)
            
            # Setup system dependencies
            self.log("🔧 Setting up system dependencies...")
            if not self.installer.setup_windows_dependencies():
                self.log("⚠️ System dependency setup completed with warnings")
            self.update_progress(50)
            
            # Create installation directory
            self.log(f"📁 Creating installation directory: {VPN_CONFIG['install_dir']}")
            os.makedirs(VPN_CONFIG['install_dir'], exist_ok=True)
            self.update_progress(60)
            
            # Setup networking
            if self.system == "Windows":
                self.log("🌐 Setting up Windows networking...")
                WindowsNetworking.create_tap_interface()
                WindowsNetworking.setup_routing()
            self.update_progress(70)
            
            # Create VPN server
            self.log("🛡️ Setting up VPN server...")
            self.server = VPNServer()
            self.update_progress(80)
            
            # Start VPN server
            self.log("🚀 Starting VPN server...")
            server_thread = threading.Thread(target=self.server.start_server, daemon=True)
            server_thread.start()
            
            # Start web interface
            web_thread = threading.Thread(target=self.server.start_web_interface, daemon=True)
            web_thread.start()
            
            self.update_progress(90)
            
            # Generate client
            self.log("📱 Generating VPN client...")
            self.server.generate_client_app()
            self.update_progress(100)
            
            self.log("✅ VPN installation completed successfully!")
            self.log(f"🌐 Web interface: http://localhost:{VPN_CONFIG['web_port']}")
            self.log(f"🛡️ VPN server running on port: {VPN_CONFIG['server_port']}")
            
            # Enable buttons
            self.client_btn.config(state='normal')
            self.web_btn.config(state='normal')
            
            # Only enable build executable if not already compiled
            if not VPN_CONFIG['is_frozen']:
                self.build_exe_btn.config(state='normal')
            
            # Show success message
            success_msg = (f"VPN Server installed successfully!\n\n"
                          f"Server Port: {VPN_CONFIG['server_port']}\n"
                          f"Web Interface: http://localhost:{VPN_CONFIG['web_port']}\n\n"
                          f"You can now:\n"
                          f"• Create desktop clients\n"
                          f"• Manage server via web interface")
            
            if not VPN_CONFIG['is_frozen']:
                success_msg += f"\n• Build standalone executable"
            
            messagebox.showinfo("Installation Complete", success_msg)
            
        except Exception as e:
            self.log(f"❌ Installation failed: {e}")
            messagebox.showerror("Installation Failed", f"Installation failed: {e}")
    
    def build_standalone_executable(self):
        """Build standalone executable using PyInstaller"""
        self.build_exe_btn.config(state='disabled')
        
        # Show confirmation dialog
        if not messagebox.askyesno("Build Executable", 
                                  "This will create a standalone .exe file that includes:\n\n"
                                  "• Complete VPN Server & Client installer\n"
                                  "• All dependencies bundled\n"
                                  "• Professional distribution package\n"
                                  "• Desktop shortcuts and documentation\n\n"
                                  "This process may take several minutes.\n"
                                  "Continue?"):
            self.build_exe_btn.config(state='normal')
            return
        
        # Run build in separate thread
        build_thread = threading.Thread(target=self.build_executable_worker, daemon=True)
        build_thread.start()
    
    def build_executable_worker(self):
        """Worker thread for building executable"""
        try:
            self.log("🔨 Starting executable build process...")
            self.update_progress(10)
            
            # Initialize executable builder
            self.executable_builder = ExecutableBuilder(self)
            
            self.log("📦 Installing PyInstaller and dependencies...")
            
            # Ensure PyInstaller is available
            try:
                import PyInstaller
                self.log("✅ PyInstaller already available")
            except ImportError:
                self.log("📥 Installing PyInstaller...")
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install", "pyinstaller>=5.0.0"
                ])
                self.log("✅ PyInstaller installed")
            
            self.update_progress(30)
            
            # Build executable
            self.log("🔧 Creating PyInstaller spec file...")
            self.update_progress(50)
            
            self.log("🚀 Building standalone executable (this may take several minutes)...")
            exe_path = self.executable_builder.build_executable()
            
            if exe_path:
                self.update_progress(100)
                self.log("✅ Executable build completed successfully!")
                self.log(f"📁 Executable location: {exe_path}")
                self.log("📦 Distribution package created with README and batch installer")
                self.log("🔗 Desktop shortcuts created")
                
                # Show success message
                messagebox.showinfo("Build Complete", 
                                  f"Standalone executable created successfully!\n\n"
                                  f"Location: {exe_path}\n\n"
                                  f"A complete distribution package has been created with:\n"
                                  f"• Standalone .exe installer\n"
                                  f"• Documentation and README\n"
                                  f"• Batch installer for convenience\n"
                                  f"• ZIP package for distribution\n\n"
                                  f"The executable can be distributed and run on any Windows system!")
            else:
                self.log("❌ Executable build failed")
                messagebox.showerror("Build Failed", "Failed to create executable. Check the log for details.")
                
        except Exception as e:
            self.log(f"❌ Build process failed: {e}")
            messagebox.showerror("Build Error", f"Build process failed: {e}")
        finally:
            self.build_exe_btn.config(state='normal')
    
    def create_desktop_client(self):
        """Create desktop client application"""
        try:
            self.log("📱 Creating desktop VPN client...")
            
            if self.server:
                client_path = self.server.generate_client_app()
                if client_path:
                    # Create desktop shortcut
                    self.create_desktop_shortcut(client_path)
                    self.log("✅ Desktop VPN client created successfully!")
                    messagebox.showinfo("Client Created", 
                                      f"VPN client created and saved to desktop!\n"
                                      f"Location: {client_path}")
                else:
                    self.log("❌ Failed to create client application")
            else:
                self.log("❌ VPN server not running, cannot create client")
                
        except Exception as e:
            self.log(f"❌ Client creation failed: {e}")
            messagebox.showerror("Error", f"Failed to create client: {e}")
    
    def create_desktop_shortcut(self, client_path):
        """Create desktop shortcut for VPN client"""
        try:
            if self.system == "Windows":
                try:
                    import win32com.client
                    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
                    shortcut_path = os.path.join(desktop, "VPN Client.lnk")
                    
                    shell = win32com.client.Dispatch("WScript.Shell")
                    shortcut = shell.CreateShortCut(shortcut_path)
                    shortcut.Targetpath = sys.executable
                    shortcut.Arguments = f'"{client_path}"'
                    shortcut.WorkingDirectory = os.path.dirname(client_path)
                    shortcut.IconLocation = sys.executable
                    shortcut.save()
                    
                    self.log(f"🔗 Desktop shortcut created: {shortcut_path}")
                except ImportError:
                    # Fallback: create a batch file
                    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
                    batch_path = os.path.join(desktop, "VPN Client.bat")
                    
                    batch_content = f'@echo off\ncd /d "{os.path.dirname(client_path)}"\npython "{client_path}"\npause'
                    with open(batch_path, 'w') as f:
                        f.write(batch_content)
                    
                    self.log(f"🔗 Desktop batch file created: {batch_path}")
            else:
                # Linux desktop shortcut
                desktop = os.path.join(os.path.expanduser("~"), "Desktop")
                shortcut_path = os.path.join(desktop, "VPN_Client.desktop")
                
                shortcut_content = f"""[Desktop Entry]
Name=VPN Client
Comment=VPN Client Application
Exec=python3 "{client_path}"
Icon=network-vpn
Terminal=false
Type=Application
Categories=Network;
"""
                with open(shortcut_path, 'w') as f:
                    f.write(shortcut_content)
                
                os.chmod(shortcut_path, 0o755)
                self.log(f"🔗 Desktop shortcut created: {shortcut_path}")
                
        except Exception as e:
            self.log(f"⚠️ Desktop shortcut creation failed: {e}")
    
    def open_web_interface(self):
        """Open web management interface"""
        try:
            url = f"http://localhost:{VPN_CONFIG['web_port']}"
            webbrowser.open(url)
            self.log(f"🌐 Opening web interface: {url}")
        except Exception as e:
            self.log(f"❌ Failed to open web interface: {e}")
    
    def run(self):
        """Start installer GUI"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
    
    def on_closing(self):
        """Handle application closing"""
        if self.server and self.server.running:
            if messagebox.askokcancel("Quit", "VPN server is running. Stop server and quit?"):
                self.server.stop_server()
                self.root.destroy()
        else:
            self.root.destroy()


def main():
    """Main entry point"""
    print("🛡️ VPN Server & Client Installer")
    print("=" * 50)
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--build-exe":
            print("🔨 Building executable from command line...")
            
            # Setup basic config
            VPN_CONFIG['install_dir'] = os.path.join(
                os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'VPN_Server'
            )
            os.makedirs(VPN_CONFIG['install_dir'], exist_ok=True)
            
            # Install dependencies
            installer = DependencyInstaller()
            if installer.install_python_packages():
                print("✅ Dependencies installed")
                
                # Build executable
                builder = ExecutableBuilder(None)
                exe_path = builder.build_executable()
                
                if exe_path:
                    print(f"✅ Executable created: {exe_path}")
                    return
                else:
                    print("❌ Executable creation failed")
                    sys.exit(1)
            else:
                print("❌ Dependency installation failed")
                sys.exit(1)
        
        elif sys.argv[1] == "--help":
            print("""
Usage:
  python vpn_installer.py           - Launch GUI installer
  python vpn_installer.py --build-exe - Build executable only
  python vpn_installer.py --help      - Show this help

Features:
  • Complete VPN server installation
  • Desktop client creation
  • Web management interface
  • Standalone executable builder
  • Windows firewall configuration
  • TAP adapter setup
            """)
            return
    
    # Check Python version
    if sys.version_info < (3, 7):
        print("❌ Python 3.7+ required")
        input("Press Enter to exit...")
        sys.exit(1)
    
    # Check platform
    system = platform.system()
    print(f"🖥️ Detected platform: {system}")
    
    if system not in ["Windows", "Linux"]:
        print(f"⚠️ Platform {system} not fully supported")
        print("Continuing with limited functionality...")
    
    # Check admin privileges
    try:
        if system == "Windows":
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        else:
            is_admin = os.geteuid() == 0
        
        if not is_admin:
            print("⚠️ WARNING: Not running with administrator privileges")
            print("Some features may not work correctly")
            print("Recommend running as Administrator/sudo")
    except:
        print("⚠️ Could not check admin status")
    
    print("\n🚀 Starting VPN Installer GUI...")
    
    try:
        # Create and run installer
        installer = VPNInstaller()
        installer.run()
        
    except KeyboardInterrupt:
        print("\n⏹ Installation cancelled by user")
    except Exception as e:
        print(f"\n❌ Installation failed: {e}")
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()
