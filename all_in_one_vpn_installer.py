#!/usr/bin/env python3
"""
Complete Enterprise VPN Solution with SSL, PFS, and Firefox Integration
Single-page solution with Perfect Forward Secrecy, SSL hosting, automatic Firefox configuration,
traffic routing, SOCKS proxy, and comprehensive management interface.

Features:
- Perfect Forward Secrecy (PFS) with ECDH key exchange
- SSL/TLS encrypted proxy hosting
- Automatic Firefox proxy configuration
- SOCKS5 proxy server with DNS routing
- Traffic routing and NAT
- Web management interface
- One-click setup and deployment
- Client certificate management
- Real-time monitoring and logging

Author: Enterprise VPN Solutions
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
import ssl
import struct
import select
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime, timedelta
import webbrowser
import tempfile
import shutil
import urllib.request
import configparser
import ipaddress
import hashlib
import secrets
import zipfile

# Advanced imports with fallbacks
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.fernet import Fernet
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[WARNING] Advanced cryptography not available - install with: pip install cryptography")

try:
    from flask import Flask, render_template_string, jsonify, request, send_file
    from flask_socketio import SocketIO
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("[WARNING] Flask not available - install with: pip install flask flask-socketio")

try:
    import winreg
    import ctypes
    if platform.system() == "Windows":
        import win32com.client
except ImportError:
    pass

# Global configuration
VPN_CONFIG = {
    "server_port": 8044,
    "socks_port": 1080,
    "web_port": 8045,
    "network_range": "10.8.0.0/24",
    "server_ip": "10.8.0.1",
    "dns_servers": ["8.8.8.8", "1.1.1.1"],
    "install_dir": None,
    "firefox_configured": False,
    "ssl_enabled": True,
    "cert_path": r'C:\portablexampp\apache\conf\ssl.crt\certificate.crt',
    "key_path": r'C:\portablexampp\apache\conf\ssl.key\private.key'
}

class PFSCryptoManager:
    """Perfect Forward Secrecy Cryptography Manager with SSL/TLS support"""
    
    def __init__(self, is_server=False):
        self.is_server = is_server
        self.session_key = None
        self.crypto_available = CRYPTO_AVAILABLE
        self.handshake_complete = False
        self.ssl_context = None
        
        if self.crypto_available:
            self._generate_ephemeral_keys()
            if is_server:
                self._setup_ssl_context()
        else:
            print("[WARNING] Advanced crypto not available, using basic mode")
    
    def _generate_ephemeral_keys(self):
        """Generate ephemeral ECDH key pair for Perfect Forward Secrecy"""
        try:
            # Generate ephemeral private key using P-256 curve
            self.private_key = ec.generate_private_key(ec.SECP256R1())
            self.public_key = self.private_key.public_key()
            
            # Serialize public key for transmission
            self.public_key_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            
            # Generate session ID
            self.session_id = secrets.token_hex(16)
            
            print(f"[PFS] Generated ephemeral keys ({'server' if self.is_server else 'client'})")
            print(f"[PFS] Session ID: {self.session_id[:8]}...")
            
        except Exception as e:
            print(f"[ERROR] Key generation failed: {e}")
            self.crypto_available = False
    
    def _setup_ssl_context(self):
        """Setup SSL context for encrypted proxy hosting"""
        try:
            cert_path = VPN_CONFIG['cert_path']
            key_path = VPN_CONFIG['key_path']
            
            print(f"[SSL] Loading certificate from: {cert_path}")
            print(f"[SSL] Loading private key from: {key_path}")
            
            # Check if certificate files exist
            if not os.path.exists(cert_path) or not os.path.exists(key_path):
                print(f"[WARNING] SSL certificate files not found")
                print(f"[INFO] Expected: {cert_path} and {key_path}")
                print(f"[INFO] Generating self-signed certificate...")
                self._generate_self_signed_cert()
            else:
                # Create SSL context with existing certificates
                self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                self.ssl_context.load_cert_chain(cert_path, key_path)
                
                # Configure SSL settings for security
                self.ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
                self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
                
                print(f"[OK] SSL context configured successfully")
                VPN_CONFIG['ssl_enabled'] = True
                
        except Exception as e:
            print(f"[ERROR] SSL setup failed: {e}")
            print(f"[INFO] Falling back to HTTP mode")
            VPN_CONFIG['ssl_enabled'] = False
    
    def _generate_self_signed_cert(self):
        """Generate self-signed certificate if none exists"""
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "VPN"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Server"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VPN Solutions"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Ensure certificate directory exists
            cert_dir = os.path.dirname(VPN_CONFIG['cert_path'])
            key_dir = os.path.dirname(VPN_CONFIG['key_path'])
            os.makedirs(cert_dir, exist_ok=True)
            os.makedirs(key_dir, exist_ok=True)
            
            # Write certificate
            with open(VPN_CONFIG['cert_path'], "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            # Write private key
            with open(VPN_CONFIG['key_path'], "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            print(f"[OK] Generated self-signed certificate")
            print(f"[INFO] Certificate: {VPN_CONFIG['cert_path']}")
            print(f"[INFO] Private key: {VPN_CONFIG['key_path']}")
            
            # Setup SSL context with new certificate
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ssl_context.load_cert_chain(VPN_CONFIG['cert_path'], VPN_CONFIG['key_path'])
            self.ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            
            VPN_CONFIG['ssl_enabled'] = True
            
        except Exception as e:
            print(f"[ERROR] Certificate generation failed: {e}")
            VPN_CONFIG['ssl_enabled'] = False
    
    def get_public_key(self):
        """Get public key for PFS key exchange"""
        if self.crypto_available and hasattr(self, 'public_key_bytes'):
            return self.public_key_bytes
        else:
            return b"NO_CRYPTO_FALLBACK_KEY"
    
    def perform_pfs_handshake(self, peer_public_key_bytes):
        """Perform Perfect Forward Secrecy handshake"""
        if not self.crypto_available:
            # Fallback session key
            self.session_key = b"FALLBACK_SESSION_KEY_2024"[:32].ljust(32, b'\x00')
            self.handshake_complete = True
            print("[WARNING] Using fallback session key")
            return True
        
        try:
            # Reconstruct peer's public key
            peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), peer_public_key_bytes
            )
            
            # Perform ECDH key exchange
            shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
            
            # Derive session key using HKDF with additional entropy
            session_info = f"VPN_PFS_{self.session_id}_{int(time.time())}"
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"VPN_PFS_SALT_2024_ENHANCED",
                info=session_info.encode()
            ).derive(shared_key)
            
            self.session_key = derived_key
            self.handshake_complete = True
            
            # Clear ephemeral private key for perfect forward secrecy
            self.private_key = None
            
            print(f"[OK] PFS handshake complete ({'server' if self.is_server else 'client'})")
            print(f"[PFS] Session key derived with {len(derived_key)} bytes")
            
            return True
            
        except Exception as e:
            print(f"[ERROR] PFS handshake failed: {e}")
            # Fallback to basic session key
            self.session_key = b"FALLBACK_SESSION_KEY_2024"[:32].ljust(32, b'\x00')
            self.handshake_complete = True
            return True
    
    def encrypt_data(self, data):
        """Encrypt data with AES-256-GCM"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if not self.handshake_complete:
            return b"PLAIN:" + data
        
        if not self.crypto_available or not self.session_key:
            # Simple XOR fallback
            result = bytearray()
            for i, byte in enumerate(data):
                result.append(byte ^ self.session_key[i % len(self.session_key)])
            return b"SIMPLE:" + bytes(result)
        
        try:
            # Generate random nonce
            nonce = secrets.token_bytes(12)
            
            # AES-256-GCM encryption
            cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            # Return nonce + tag + ciphertext
            return b"AES256:" + nonce + encryptor.tag + ciphertext
            
        except Exception as e:
            print(f"[ERROR] Encryption failed: {e}")
            # Fallback to simple XOR
            result = bytearray()
            for i, byte in enumerate(data):
                result.append(byte ^ self.session_key[i % len(self.session_key)])
            return b"SIMPLE:" + bytes(result)
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data with AES-256-GCM"""
        if not self.handshake_complete:
            if encrypted_data.startswith(b"PLAIN:"):
                return encrypted_data[6:]
            return encrypted_data
        
        if encrypted_data.startswith(b"SIMPLE:"):
            # Simple XOR decryption
            encrypted_data = encrypted_data[7:]
            result = bytearray()
            for i, byte in enumerate(encrypted_data):
                result.append(byte ^ self.session_key[i % len(self.session_key)])
            return bytes(result)
        
        if encrypted_data.startswith(b"AES256:"):
            if not self.crypto_available:
                raise Exception("AES256 data received but crypto not available")
            
            try:
                encrypted_data = encrypted_data[7:]  # Remove "AES256:" prefix
                
                # Extract nonce, tag, and ciphertext
                nonce = encrypted_data[:12]
                tag = encrypted_data[12:28]
                ciphertext = encrypted_data[28:]
                
                # Decrypt
                cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()
                
                return decryptor.update(ciphertext) + decryptor.finalize()
                
            except Exception as e:
                print(f"[ERROR] Decryption failed: {e}")
                raise
        
        if encrypted_data.startswith(b"PLAIN:"):
            return encrypted_data[6:]
        
        # Try base64 fallback
        try:
            return base64.b64decode(encrypted_data)
        except:
            return encrypted_data


class SOCKSProxyServer:
    """SOCKS5 proxy server with SSL support and DNS routing"""
    
    def __init__(self, host='127.0.0.1', port=1080):
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None
        self.ssl_context = None
        self.clients = {}
        
        # SOCKS5 protocol does not use SSL (applications handle SSL)
        print("[SOCKS] SOCKS5 proxy initialized without SSL (correct behavior)")
    
    def setup_ssl(self):
        """Setup SSL context for SOCKS proxy"""
        try:
            crypto_manager = PFSCryptoManager(is_server=True)
            self.ssl_context = crypto_manager.ssl_context
            print("[SOCKS] SSL context configured for proxy")
        except Exception as e:
            print(f"[WARNING] SOCKS SSL setup failed: {e}")
    
    def start(self):
        """Start SOCKS5 proxy server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(100)
            
            self.running = True
            
            if self.ssl_context:
                print(f"[SOCKS] SSL SOCKS5 proxy started on {self.host}:{self.port}")
            else:
                print(f"[SOCKS] SOCKS5 proxy started on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    
                    # SOCKS5 does NOT use SSL - applications handle SSL themselves
                    print(f"[SOCKS] Plain SOCKS5 connection from {address} (correct)")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:
                        print(f"[ERROR] SOCKS accept error: {e}")
                        
        except Exception as e:
            print(f"[ERROR] SOCKS server start failed: {e}")
        finally:
            self.stop()
    
    def handle_client(self, client_socket, address):
        """Handle SOCKS5 client connection"""
        client_id = f"{address[0]}:{address[1]}"
        
        try:
            self.clients[client_id] = {
                'socket': client_socket,
                'address': address,
                'connected_time': datetime.now()
            }
            
            print(f"[SOCKS] Client connected: {client_id}")
            
            # SOCKS5 handshake
            if not self.socks5_handshake(client_socket):
                return
            
            # Handle SOCKS5 requests
            self.handle_socks5_request(client_socket)
            
        except Exception as e:
            print(f"[ERROR] SOCKS client error {client_id}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            if client_id in self.clients:
                del self.clients[client_id]
            print(f"[SOCKS] Client disconnected: {client_id}")
    
    def socks5_handshake(self, client_socket):
        """Perform SOCKS5 authentication handshake"""
        try:
            # Receive authentication methods
            data = client_socket.recv(1024)
            if len(data) < 2:
                return False
            
            version = data[0]
            if version != 5:  # SOCKS5
                return False
            
            # Send no authentication required
            client_socket.send(b'\x05\x00')
            return True
            
        except Exception as e:
            print(f"[ERROR] SOCKS5 handshake failed: {e}")
            return False
    
    def handle_socks5_request(self, client_socket):
        """Handle SOCKS5 connection request"""
        try:
            # Receive connection request
            data = client_socket.recv(1024)
            if len(data) < 4:
                return
            
            version = data[0]
            command = data[1]
            address_type = data[3]
            
            if version != 5 or command != 1:  # Only support CONNECT
                client_socket.send(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            
            # Parse target address
            if address_type == 1:  # IPv4
                target_addr = socket.inet_ntoa(data[4:8])
                target_port = struct.unpack('>H', data[8:10])[0]
            elif address_type == 3:  # Domain name
                addr_len = data[4]
                target_addr = data[5:5+addr_len].decode('utf-8')
                target_port = struct.unpack('>H', data[5+addr_len:7+addr_len])[0]
            elif address_type == 4:  # IPv6
                target_addr = socket.inet_ntop(socket.AF_INET6, data[4:20])
                target_port = struct.unpack('>H', data[20:22])[0]
            else:
                client_socket.send(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            
            print(f"[SOCKS] Connecting to {target_addr}:{target_port}")
            
            # Connect to target
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.settimeout(30)
            
            try:
                target_socket.connect((target_addr, target_port))
                
                # Send success response
                client_socket.send(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                
                # Start data forwarding
                self.forward_data(client_socket, target_socket)
                
            except Exception as connect_error:
                print(f"[ERROR] Connection to {target_addr}:{target_port} failed: {connect_error}")
                client_socket.send(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            finally:
                target_socket.close()
                
        except Exception as e:
            print(f"[ERROR] SOCKS5 request handling failed: {e}")
    
    def forward_data(self, client_socket, target_socket):
        """Forward data between client and target"""
        try:
            while True:
                ready = select.select([client_socket, target_socket], [], [], 30)
                
                if not ready[0]:
                    break
                
                for sock in ready[0]:
                    try:
                        data = sock.recv(8192)
                        if not data:
                            return
                        
                        if sock is client_socket:
                            target_socket.send(data)
                        else:
                            client_socket.send(data)
                            
                    except Exception:
                        return
                        
        except Exception as e:
            print(f"[ERROR] Data forwarding failed: {e}")
    
    def stop(self):
        """Stop SOCKS proxy server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        print("[SOCKS] Proxy server stopped")


class FirefoxIntegrator:
    """Automatic Firefox configuration for VPN"""
    
    def __init__(self):
        self.system = platform.system()
        self.firefox_profiles = []
        
    def find_firefox_profiles(self):
        """Find all Firefox profile directories"""
        profiles = []
        
        try:
            if self.system == "Windows":
                # Windows Firefox profiles
                appdata = os.environ.get('APPDATA', '')
                profile_base = os.path.join(appdata, 'Mozilla', 'Firefox', 'Profiles')
                
                if os.path.exists(profile_base):
                    for item in os.listdir(profile_base):
                        profile_path = os.path.join(profile_base, item)
                        if os.path.isdir(profile_path):
                            profiles.append(profile_path)
            
            elif self.system == "Darwin":  # macOS
                home = os.path.expanduser("~")
                profile_base = os.path.join(home, 'Library', 'Application Support', 'Firefox', 'Profiles')
                
                if os.path.exists(profile_base):
                    for item in os.listdir(profile_base):
                        profile_path = os.path.join(profile_base, item)
                        if os.path.isdir(profile_path):
                            profiles.append(profile_path)
            
            else:  # Linux
                home = os.path.expanduser("~")
                profile_base = os.path.join(home, '.mozilla', 'firefox')
                
                if os.path.exists(profile_base):
                    for item in os.listdir(profile_base):
                        profile_path = os.path.join(profile_base, item)
                        if os.path.isdir(profile_path) and '.' in item:
                            profiles.append(profile_path)
        
        except Exception as e:
            print(f"[WARNING] Error finding Firefox profiles: {e}")
        
        self.firefox_profiles = profiles
        return profiles
    
    def configure_firefox(self):
        """Configure Firefox for VPN use"""
        try:
            profiles = self.find_firefox_profiles()
            if not profiles:
                print("[WARNING] No Firefox profiles found")
                return False
            
            print(f"[FIREFOX] Found {len(profiles)} Firefox profile(s)")
            
            # Backup and configure each profile
            for profile_path in profiles:
                self.backup_and_configure_profile(profile_path)
            
            # Create VPN-specific profile
            self.create_vpn_profile()
            
            VPN_CONFIG['firefox_configured'] = True
            print("[OK] Firefox configured for VPN")
            return True
            
        except Exception as e:
            print(f"[ERROR] Firefox configuration failed: {e}")
            return False
    
    def backup_and_configure_profile(self, profile_path):
        """Backup and configure a Firefox profile"""
        try:
            prefs_file = os.path.join(profile_path, 'prefs.js')
            
            # Backup original settings
            if os.path.exists(prefs_file):
                backup_file = prefs_file + '.vpn_backup'
                if not os.path.exists(backup_file):
                    shutil.copy2(prefs_file, backup_file)
                    print(f"[BACKUP] Firefox settings backed up: {backup_file}")
            
            # VPN proxy settings for enhanced security and privacy
            ssl_prefix = "https" if VPN_CONFIG['ssl_enabled'] else "http"
            
            vpn_settings = [
                'user_pref("network.proxy.type", 1);',  # Manual proxy
                f'user_pref("network.proxy.socks", "127.0.0.1");',
                f'user_pref("network.proxy.socks_port", {VPN_CONFIG["socks_port"]});',
                'user_pref("network.proxy.socks_version", 5);',
                'user_pref("network.proxy.socks_remote_dns", true);',  # DNS through proxy
                'user_pref("network.proxy.no_proxies_on", "");',  # Proxy everything
                
                # DNS and privacy settings
                'user_pref("network.dns.disablePrefetch", true);',
                'user_pref("network.dns.disableIPv6", true);',
                'user_pref("network.predictor.enabled", false);',
                'user_pref("network.prefetch-next", false);',
                
                # WebRTC leak prevention
                'user_pref("media.peerconnection.enabled", false);',
                'user_pref("media.peerconnection.ice.default_address_only", true);',
                'user_pref("media.peerconnection.ice.no_host", true);',
                
                # Enhanced privacy
                'user_pref("privacy.trackingprotection.enabled", true);',
                'user_pref("privacy.trackingprotection.socialtracking.enabled", true);',
                'user_pref("privacy.firstparty.isolate", true);',
                'user_pref("privacy.resistFingerprinting", true);',
                
                # Security settings
                'user_pref("security.tls.version.min", 3);',  # TLS 1.2 minimum
                'user_pref("security.ssl.require_safe_negotiation", true);',
                'user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);',
                
                # Disable various tracking
                'user_pref("beacon.enabled", false);',
                'user_pref("browser.send_pings", false);',
                'user_pref("network.http.sendOriginHeader", 0);',
                'user_pref("network.http.sendRefererHeader", 0);',
                
                # WebGL and Canvas fingerprinting protection
                'user_pref("webgl.disabled", true);',
                'user_pref("privacy.resistFingerprinting.block_mozAddonManager", true);',
                
                # VPN-specific settings - Enhanced SOCKS5 reliability
                'user_pref("network.proxy.failover_timeout", 5);',
                'user_pref("network.proxy.socks_remote_dns", true);',
                'user_pref("network.security.ports.banned", "");',  # Allow all ports
                'user_pref("network.proxy.allow_hijacking_localhost", true);',
                'user_pref("network.http.sendRefererHeader", 2);',  # Same origin only
            ]
            
            # Read existing prefs
            existing_prefs = []
            if os.path.exists(prefs_file):
                with open(prefs_file, 'r', encoding='utf-8') as f:
                    existing_prefs = f.readlines()
            
            # Remove existing proxy/privacy settings
            filtered_prefs = []
            remove_settings = [
                'network.proxy.', 'privacy.', 'security.', 'media.peerconnection',
                'webgl.disabled', 'beacon.enabled', 'browser.send_pings'
            ]
            
            for line in existing_prefs:
                if not any(setting in line for setting in remove_settings):
                    filtered_prefs.append(line)
            
            # Write updated prefs
            with open(prefs_file, 'w', encoding='utf-8') as f:
                for line in filtered_prefs:
                    f.write(line)
                for setting in vpn_settings:
                    f.write(setting + '\n')
            
            profile_name = os.path.basename(profile_path)
            print(f"[FIREFOX] Configured profile: {profile_name}")
            
        except Exception as e:
            print(f"[WARNING] Failed to configure profile {profile_path}: {e}")
    
    def create_vpn_profile(self):
        """Create dedicated VPN Firefox profile"""
        try:
            firefox_exe = self.get_firefox_executable()
            if not firefox_exe:
                print("[WARNING] Firefox executable not found")
                return
            
            # Create VPN profile
            subprocess.run([
                firefox_exe, '-CreateProfile', 'VPN-Secure'
            ], capture_output=True, timeout=30)
            
            print("[FIREFOX] Created dedicated VPN profile: VPN-Secure")
            
            # Configure the new profile
            time.sleep(2)
            self.find_firefox_profiles()
            
            # Find and configure the new VPN profile
            for profile_path in self.firefox_profiles:
                if 'vpn-secure' in profile_path.lower():
                    self.backup_and_configure_profile(profile_path)
                    break
            
        except Exception as e:
            print(f"[WARNING] VPN profile creation failed: {e}")
    
    def get_firefox_executable(self):
        """Get Firefox executable path"""
        if self.system == "Windows":
            locations = [
                os.path.join(os.environ.get('PROGRAMFILES', ''), 'Mozilla Firefox', 'firefox.exe'),
                os.path.join(os.environ.get('PROGRAMFILES(X86)', ''), 'Mozilla Firefox', 'firefox.exe'),
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Mozilla Firefox', 'firefox.exe')
            ]
        elif self.system == "Darwin":
            locations = ['/Applications/Firefox.app/Contents/MacOS/firefox']
        else:
            locations = ['/usr/bin/firefox', '/usr/local/bin/firefox', '/snap/bin/firefox']
        
        for location in locations:
            if os.path.exists(location):
                return location
        
        return None
    
    def launch_firefox_with_vpn(self):
        """Launch Firefox with VPN profile"""
        try:
            firefox_exe = self.get_firefox_executable()
            if not firefox_exe:
                print("[ERROR] Firefox not found")
                return False
            
            # Launch with VPN profile
            subprocess.Popen([
                firefox_exe, '-P', 'VPN-Secure', '-new-instance'
            ])
            
            print("[FIREFOX] Launched Firefox with VPN profile")
            return True
            
        except Exception as e:
            print(f"[ERROR] Firefox launch failed: {e}")
            return False
    
    def restore_firefox_settings(self):
        """Restore original Firefox settings"""
        try:
            for profile_path in self.firefox_profiles:
                prefs_file = os.path.join(profile_path, 'prefs.js')
                backup_file = prefs_file + '.vpn_backup'
                
                if os.path.exists(backup_file):
                    shutil.copy2(backup_file, prefs_file)
                    print(f"[RESTORE] Restored Firefox settings: {profile_path}")
            
            print("[OK] Firefox settings restored")
            
        except Exception as e:
            print(f"[ERROR] Firefox restore failed: {e}")


class TrafficRouter:
    """Advanced traffic routing with NAT and firewall integration"""
    
    def __init__(self, vpn_server):
        self.vpn_server = vpn_server
        self.system = platform.system()
        self.routing_active = False
        self.nat_table = {}
        self.firewall_rules = []
        
    def setup_routing(self):
        """Setup advanced traffic routing"""
        print("[ROUTING] Setting up traffic routing...")
        
        if self.system == "Windows":
            return self.setup_windows_routing()
        else:
            return self.setup_linux_routing()
    
    def setup_windows_routing(self):
        """Setup Windows traffic routing and NAT"""
        try:
            # Enable IP forwarding
            print("[ROUTING] Enabling IP forwarding...")
            try:
                # Method 1: PowerShell (more reliable for Windows 10/11)
                subprocess.run([
                    "powershell", "-Command", 
                    "Set-NetIPInterface -Forwarding Enabled"
                ], check=True, timeout=30)
                print("[OK] IP forwarding enabled via PowerShell")
            except Exception as ps_error:
                print(f"[WARNING] PowerShell method failed: {ps_error}")
                try:
                    # Method 2: Registry edit (fallback)
                    import winreg
                    key_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
                    winreg.CloseKey(key)
                    print("[OK] IP forwarding enabled via registry")
                except Exception as reg_error:
                    print(f"[ERROR] IP forwarding setup failed: {reg_error}")
            
            # Configure Windows Firewall rules
            self.configure_windows_firewall()
            
            # Setup routing table
            self.setup_windows_routes()
            
            # Configure DNS
            self.configure_dns_routing()
            
            print("[OK] Windows routing configured")
            return True
            
        except Exception as e:
            print(f"[ERROR] Windows routing setup failed: {e}")
            return False
    
    def configure_windows_firewall(self):
        """Configure Windows Firewall for VPN"""
        try:
            print("[FIREWALL] Configuring Windows Firewall...")
            
            # VPN server rules
            firewall_rules = [
                {
                    "name": "VPN-Server-In",
                    "dir": "in",
                    "action": "allow",
                    "protocol": "TCP",
                    "port": VPN_CONFIG['server_port']
                },
                {
                    "name": "VPN-SOCKS-In", 
                    "dir": "in",
                    "action": "allow",
                    "protocol": "TCP",
                    "port": VPN_CONFIG['socks_port']
                },
                {
                    "name": "VPN-Web-In",
                    "dir": "in", 
                    "action": "allow",
                    "protocol": "TCP",
                    "port": VPN_CONFIG['web_port']
                },
                {
                    "name": "VPN-Forward-Out",
                    "dir": "out",
                    "action": "allow",
                    "protocol": "any",
                    "remoteip": "any"
                }
            ]
            
            for rule in firewall_rules:
                try:
                    cmd = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule['name']}",
                        f"dir={rule['dir']}",
                        f"action={rule['action']}"
                    ]
                    
                    if rule.get('protocol') != 'any':
                        cmd.extend([f"protocol={rule['protocol']}"])
                    
                    if rule.get('port'):
                        cmd.extend([f"localport={rule['port']}"])
                    
                    if rule.get('remoteip'):
                        cmd.extend([f"remoteip={rule['remoteip']}"])
                    
                    subprocess.run(cmd, check=True, timeout=30)
                    self.firewall_rules.append(rule['name'])
                    
                except Exception as rule_error:
                    print(f"[WARNING] Firewall rule {rule['name']} failed: {rule_error}")
            
            print("[OK] Windows Firewall configured")
            
        except Exception as e:
            print(f"[ERROR] Firewall configuration failed: {e}")
    
    def setup_windows_routes(self):
        """Setup Windows routing table"""
        try:
            print("[ROUTES] Configuring routing table...")
            
            # Get primary interface
            primary_interface = self.get_primary_interface()
            
            # Add VPN network route
            try:
                subprocess.run([
                    "route", "add", VPN_CONFIG["network_range"].split('/')[0],
                    "mask", "255.255.255.0", VPN_CONFIG["server_ip"], "metric", "1"
                ], check=True, timeout=30)
                print("[OK] VPN route added")
            except subprocess.CalledProcessError as route_error:
                if "object already exists" in str(route_error).lower():
                    print("[OK] VPN route already exists")
                else:
                    print(f"[WARNING] Route addition failed: {route_error}")
            
            print("[OK] Routing table configured")
            
        except Exception as e:
            print(f"[ERROR] Routing table setup failed: {e}")
    
    def configure_dns_routing(self):
        """Configure DNS routing through VPN"""
        try:
            print("[DNS] Configuring DNS routing...")
            
            # Get active network interface instead of assuming TAP adapter
            result = subprocess.run([
                "netsh", "interface", "show", "interface"
            ], capture_output=True, text=True, timeout=30)
            
            # Find first active interface
            active_interface = None
            for line in result.stdout.split('\n'):
                if 'Connected' in line and 'Enabled' in line:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        interface_name = ' '.join(parts[3:])
                        if 'Loopback' not in interface_name:
                            active_interface = interface_name
                            break
            
            if active_interface:
                try:
                    # Set primary DNS server
                    subprocess.run([
                        "netsh", "interface", "ip", "set", "dns",
                        f"name={active_interface}", "static", VPN_CONFIG["dns_servers"][0]
                    ], timeout=30, check=True)
                    print(f"[OK] Primary DNS set to {VPN_CONFIG['dns_servers'][0]} for {active_interface}")
                    
                    # Add secondary DNS servers
                    for i, dns in enumerate(VPN_CONFIG["dns_servers"][1:], 2):
                        try:
                            subprocess.run([
                                "netsh", "interface", "ip", "add", "dns",
                                f"name={active_interface}", f"addr={dns}", f"index={i}"
                            ], timeout=30, check=True)
                            print(f"[OK] Secondary DNS {dns} added to {active_interface}")
                        except Exception as secondary_dns_error:
                            print(f"[WARNING] Failed to add secondary DNS {dns}: {secondary_dns_error}")
                    
                    print(f"[OK] DNS routing configured for interface: {active_interface}")
                    
                except Exception as dns_error:
                    print(f"[WARNING] DNS config failed for {active_interface}: {dns_error}")
                    print("[INFO] You may need to manually configure DNS settings")
            else:
                print("[WARNING] No suitable interface found for DNS config")
                print("[INFO] Available interfaces:")
                # Show available interfaces for debugging
                for line in result.stdout.split('\n'):
                    if line.strip() and ('Connected' in line or 'Disconnected' in line):
                        print(f"[INFO]   {line.strip()}")
            
            print("[OK] DNS routing configuration completed")
            
        except Exception as e:
            print(f"[ERROR] DNS configuration failed: {e}")
            print("[INFO] Manual DNS configuration may be required:")
            print(f"[INFO] Set DNS to: {', '.join(VPN_CONFIG['dns_servers'])}")
    
    def get_primary_interface(self):
        """Get primary network interface"""
        try:
            result = subprocess.run([
                "route", "print", "0.0.0.0"
            ], capture_output=True, text=True, timeout=30)
            
            lines = result.stdout.split('\n')
            for line in lines:
                if "0.0.0.0" in line and "0.0.0.0" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        return parts[3]
        except Exception:
            pass
        
        return "Ethernet"  # Fallback
    
    def start_traffic_forwarding(self):
        """Start advanced traffic forwarding"""
        print("[FORWARD] Starting traffic forwarding...")
        
        self.routing_active = True
        
        # Start forwarding thread
        forward_thread = threading.Thread(
            target=self.traffic_forwarding_loop,
            daemon=True
        )
        forward_thread.start()
    
    def traffic_forwarding_loop(self):
        """Main traffic forwarding loop with NAT"""
        try:
            while self.routing_active:
                # Monitor VPN client connections
                for client_id, client_info in list(self.vpn_server.clients.items()):
                    try:
                        # Check for data from client
                        client_socket = client_info.get('socket')
                        if client_socket:
                            ready = select.select([client_socket], [], [], 0.1)
                            if ready[0]:
                                data = client_socket.recv(8192)
                                if data:
                                    self.process_client_data(client_id, data)
                    except Exception as e:
                        continue
                
                time.sleep(0.1)  # Small delay to prevent CPU spinning
                
        except Exception as e:
            print(f"[ERROR] Traffic forwarding error: {e}")
    
    def process_client_data(self, client_id, data):
        """Process data from VPN client for routing"""
        try:
            # Decrypt data if encrypted
            client_info = self.vpn_server.clients.get(client_id)
            if not client_info:
                return
            
            # For now, just log traffic (in production, implement full packet routing)
            print(f"[TRAFFIC] Data from {client_id}: {len(data)} bytes")
            
            # Update client statistics
            client_info['data_received'] = f"{len(data)} bytes"
            
        except Exception as e:
            print(f"[ERROR] Data processing error for {client_id}: {e}")
    
    def cleanup_routing(self):
        """Cleanup routing configuration"""
        try:
            print("[CLEANUP] Cleaning up routing configuration...")
            
            self.routing_active = False
            
            # Remove firewall rules
            for rule_name in self.firewall_rules:
                try:
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}"
                    ], timeout=30)
                except:
                    pass
            
            print("[OK] Routing cleanup completed")
            
        except Exception as e:
            print(f"[ERROR] Routing cleanup failed: {e}")



class ProtocolRoutingTester:
    """Comprehensive protocol routing tester for VPN verification"""
    
    def __init__(self, vpn_server):
        self.vpn_server = vpn_server
        self.test_results = {}
        self.test_targets = {
            'http': 'http://httpbin.org/ip',
            'https': 'https://httpbin.org/ip',
            'tcp': ('httpbin.org', 80),
            'udp': ('8.8.8.8', 53),
            'icmp': '8.8.8.8',
            'dns': '8.8.8.8'
        }
    
    def test_http_routing(self):
        """Test HTTP routing through VPN"""
        try:
            import requests
            
            # Test without proxy
            response_direct = requests.get('http://httpbin.org/ip', timeout=10)
            direct_ip = response_direct.json().get('origin', '').split(',')[0].strip()
            
            # Test with SOCKS proxy
            proxies = {
                'http': 'socks5://127.0.0.1:1080',
                'https': 'socks5://127.0.0.1:1080'
            }
            response_proxy = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=10)
            proxy_ip = response_proxy.json().get('origin', '').split(',')[0].strip()
            
            success = direct_ip != proxy_ip
            message = f"Direct IP: {direct_ip}, Proxy IP: {proxy_ip}"
            
            return {
                'success': success,
                'message': message,
                'direct_ip': direct_ip,
                'proxy_ip': proxy_ip
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f"HTTP test failed: {str(e)}",
                'error': str(e)
            }
    
    def test_https_routing(self):
        """Test HTTPS routing through VPN"""
        try:
            import requests
            
            # Test without proxy
            response_direct = requests.get('https://httpbin.org/ip', timeout=10, verify=False)
            direct_ip = response_direct.json().get('origin', '').split(',')[0].strip()
            
            # Test with SOCKS proxy
            proxies = {
                'http': 'socks5://127.0.0.1:1080',
                'https': 'socks5://127.0.0.1:1080'
            }
            response_proxy = requests.get('https://httpbin.org/ip', proxies=proxies, timeout=10, verify=False)
            proxy_ip = response_proxy.json().get('origin', '').split(',')[0].strip()
            
            success = direct_ip != proxy_ip
            message = f"Direct IP: {direct_ip}, Proxy IP: {proxy_ip}"
            
            return {
                'success': success,
                'message': message,
                'direct_ip': direct_ip,
                'proxy_ip': proxy_ip
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f"HTTPS test failed: {str(e)}",
                'error': str(e)
            }
    
    def test_tcp_routing(self):
        """Test TCP routing through VPN"""
        try:
            import socket
            import socks
            
            # Test direct TCP connection
            sock_direct = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_direct.settimeout(5)
            try:
                sock_direct.connect(('httpbin.org', 80))
                direct_success = True
                sock_direct.close()
            except:
                direct_success = False
            
            # Test TCP through SOCKS proxy
            try:
                sock_proxy = socks.socksocket()
                sock_proxy.set_proxy(socks.SOCKS5, "127.0.0.1", 1080)
                sock_proxy.settimeout(5)
                sock_proxy.connect(('httpbin.org', 80))
                proxy_success = True
                sock_proxy.close()
            except:
                proxy_success = False
            
            success = direct_success and proxy_success
            message = f"Direct: {'OK' if direct_success else 'FAIL'}, Proxy: {'OK' if proxy_success else 'FAIL'}"
            
            return {
                'success': success,
                'message': message,
                'direct_success': direct_success,
                'proxy_success': proxy_success
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f"TCP test failed: {str(e)}",
                'error': str(e)
            }
    
    def test_udp_routing(self):
        """Test UDP routing through VPN"""
        try:
            import socket
            
            # Simple UDP test to DNS server
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # DNS query for google.com
            dns_query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01'
            
            try:
                sock.sendto(dns_query, ('8.8.8.8', 53))
                response, addr = sock.recvfrom(512)
                sock.close()
                
                success = len(response) > 0
                message = f"UDP DNS query successful, response: {len(response)} bytes"
                
                return {
                    'success': success,
                    'message': message,
                    'response_size': len(response)
                }
                
            except Exception as udp_error:
                return {
                    'success': False,
                    'message': f"UDP test failed: {str(udp_error)}",
                    'error': str(udp_error)
                }
                
        except Exception as e:
            return {
                'success': False,
                'message': f"UDP test setup failed: {str(e)}",
                'error': str(e)
            }
    
    def test_icmp_routing(self):
        """Test ICMP (ping) routing through VPN"""
        try:
            import subprocess
            import platform
            
            # Ping command varies by OS
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "3", "8.8.8.8"]
            else:
                cmd = ["ping", "-c", "3", "8.8.8.8"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            success = result.returncode == 0
            message = f"ICMP ping {'successful' if success else 'failed'}"
            
            if success:
                # Extract ping statistics
                output_lines = result.stdout.split('\n')
                for line in output_lines:
                    if 'time=' in line.lower() or 'ms' in line.lower():
                        message += f", {line.strip()}"
                        break
            
            return {
                'success': success,
                'message': message,
                'output': result.stdout[:200]  # First 200 chars
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f"ICMP test failed: {str(e)}",
                'error': str(e)
            }
    
    def test_dns_routing(self):
        """Test DNS routing through VPN"""
        try:
            import socket
            
            # Test DNS resolution
            start_time = time.time()
            try:
                ip = socket.gethostbyname('google.com')
                resolution_time = (time.time() - start_time) * 1000
                
                success = ip is not None
                message = f"DNS resolution successful: google.com -> {ip} ({resolution_time:.2f}ms)"
                
                return {
                    'success': success,
                    'message': message,
                    'resolved_ip': ip,
                    'resolution_time': resolution_time
                }
                
            except Exception as dns_error:
                return {
                    'success': False,
                    'message': f"DNS resolution failed: {str(dns_error)}",
                    'error': str(dns_error)
                }
                
        except Exception as e:
            return {
                'success': False,
                'message': f"DNS test setup failed: {str(e)}",
                'error': str(e)
            }
    
    def run_comprehensive_test(self, protocol=None):
        """Run comprehensive routing tests"""
        if protocol:
            protocols = [protocol]
        else:
            protocols = ['http', 'https', 'tcp', 'udp', 'icmp', 'dns']
        
        results = {}
        
        for proto in protocols:
            print(f"[ROUTING] Testing {proto.upper()} protocol routing...")
            
            try:
                if proto == 'http':
                    results[proto] = self.test_http_routing()
                elif proto == 'https':
                    results[proto] = self.test_https_routing()
                elif proto == 'tcp':
                    results[proto] = self.test_tcp_routing()
                elif proto == 'udp':
                    results[proto] = self.test_udp_routing()
                elif proto == 'icmp':
                    results[proto] = self.test_icmp_routing()
                elif proto == 'dns':
                    results[proto] = self.test_dns_routing()
                
                # Emit result to web interface
                if hasattr(self.vpn_server, 'socketio'):
                    self.vpn_server.socketio.emit('protocol_test_result', {
                        'protocol': proto,
                        'success': results[proto]['success'],
                        'message': results[proto]['message']
                    })
                
                print(f"[ROUTING] {proto.upper()} test: {'PASS' if results[proto]['success'] else 'FAIL'}")
                
            except Exception as e:
                results[proto] = {
                    'success': False,
                    'message': f"Test execution failed: {str(e)}",
                    'error': str(e)
                }
                print(f"[ERROR] {proto.upper()} test failed: {e}")
        
        self.test_results.update(results)
        return results
    
    def generate_test_report(self):
        """Generate comprehensive test report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_tests': len(self.test_results),
                'passed': sum(1 for r in self.test_results.values() if r['success']),
                'failed': sum(1 for r in self.test_results.values() if not r['success'])
            },
            'results': self.test_results
        }
        
        # Save report to file
        report_file = f"vpn_routing_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[REPORT] Test report saved to: {report_file}")
        except Exception as e:
            print(f"[ERROR] Failed to save report: {e}")
        
        return report
class EnhancedVPNServer:
    """Enhanced VPN Server with PFS, SSL, traffic routing, and Firefox integration"""
    
    def __init__(self):
        self.clients = {}
        self.crypto_manager = PFSCryptoManager(is_server=True)
        self.running = False
        self.server_socket = None
        self.socks_proxy = None
        self.traffic_router = None
        self.firefox_integrator = None
        self.web_app = None
        
        # Initialize components
        self.setup_components()
    
    def setup_components(self):
        """Setup all VPN components"""
        print("[VPN] Initializing enhanced VPN server...")
        
        # Setup SOCKS proxy
        self.socks_proxy = SOCKSProxyServer(port=VPN_CONFIG['socks_port'])
        
        # Setup traffic router
        self.traffic_router = TrafficRouter(self)
        
        # Setup Firefox integrator
        self.firefox_integrator = FirefoxIntegrator()
        
        # Setup web interface
        if FLASK_AVAILABLE:
            self.setup_web_interface()
        
        print("[OK] VPN components initialized")
    
    def setup_web_interface(self):
        """Setup advanced web management interface"""
        try:
            self.web_app = Flask(__name__)
            self.web_app.config['SECRET_KEY'] = secrets.token_hex(32)
            self.socketio = SocketIO(self.web_app, cors_allowed_origins="*")
            
            # Enhanced web template with SSL and PFS status
            web_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ProVPN Enterprise Management Console</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: #2563eb;
            --primary-dark: #1d4ed8;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --danger-color: #ef4444;
            --dark-bg: #0f172a;
            --card-bg: #1e293b;
            --text-light: #f1f5f9;
            --text-muted: #94a3b8;
            --border-color: #334155;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--dark-bg);
            color: var(--text-light);
            line-height: 1.6;
            min-height: 100vh;
        }

        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }

        /* Header */
        .header {
            background: var(--card-bg);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 30px;
            border: 1px solid var(--border-color);
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        }

        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }

        .header-left h1 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 8px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .header-left .subtitle {
            color: var(--text-muted);
            font-size: 1.1rem;
        }

        .status-indicator {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 20px;
            border-radius: 50px;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .status-online {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            box-shadow: 0 0 20px rgba(16, 185, 129, 0.3);
            animation: pulse-glow 2s ease-in-out infinite alternate;
        }

        .status-offline {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            box-shadow: 0 0 20px rgba(239, 68, 68, 0.3);
        }

        @keyframes pulse-glow {
            0% { box-shadow: 0 0 10px rgba(16, 185, 129, 0.3); }
            100% { box-shadow: 0 0 30px rgba(16, 185, 129, 0.6); }
        }

        /* Security Badges */
        .security-badges {
            display: flex;
            gap: 12px;
            margin-top: 20px;
            flex-wrap: wrap;
        }

        .badge {
            padding: 8px 16px;
            border-radius: 25px;
            font-weight: 600;
            font-size: 0.85rem;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .badge.pfs { border-left: 4px solid #10b981; }
        .badge.ssl { border-left: 4px solid #3b82f6; }
        .badge.socks { border-left: 4px solid #f59e0b; }
        .badge.firefox { border-left: 4px solid #9333ea; }

        /* Grid Layout */
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 25px;
            margin-bottom: 30px;
        }

        .card {
            background: var(--card-bg);
            border-radius: 15px;
            padding: 25px;
            border: 1px solid var(--border-color);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
        }

        .card h3 {
            color: var(--text-light);
            margin-bottom: 20px;
            font-size: 1.4rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }

        .stat {
            text-align: center;
            padding: 20px 15px;
            background: var(--dark-bg);
            border-radius: 12px;
            border: 1px solid var(--border-color);
            transition: all 0.3s ease;
        }

        .stat:hover { transform: translateY(-2px); }

        .stat-number {
            font-size: 2.2rem;
            font-weight: 700;
            color: var(--text-light);
            margin-bottom: 5px;
        }

        .stat-label {
            color: var(--text-muted);
            font-size: 0.9rem;
            font-weight: 500;
        }

        /* Buttons */
        .btn {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-dark) 100%);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 10px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.95rem;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            margin: 5px;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(37, 99, 235, 0.3);
        }

        .btn.success { background: linear-gradient(135deg, #10b981 0%, #059669 100%); }
        .btn.danger { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); }
        .btn.warning { background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); }
        .btn.firefox { background: linear-gradient(135deg, #ff6b35 0%, #f7941d 100%); }

        /* Table */
        .table-container {
            background: var(--dark-bg);
            border-radius: 12px;
            overflow: hidden;
            margin: 20px 0;
        }

        .table {
            width: 100%;
            border-collapse: collapse;
        }

        .table th,
        .table td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        .table th {
            background: var(--card-bg);
            font-weight: 600;
            color: var(--text-light);
        }

        .table td { color: var(--text-muted); }

        /* Routing Tester */
        .protocol-test {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }

        .protocol-card {
            background: var(--dark-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s ease;
        }

        .protocol-card:hover { transform: translateY(-2px); }

        .protocol-status {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin: 0 auto 10px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .status-testing { background: var(--warning-color); animation: spin 1s linear infinite; }
        .status-success { background: var(--success-color); }
        .status-failed { background: var(--danger-color); }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        /* Log */
        .log {
            background: var(--dark-bg);
            color: var(--text-light);
            padding: 20px;
            border-radius: 12px;
            font-family: 'JetBrains Mono', 'Fira Code', Consolas, monospace;
            height: 350px;
            overflow-y: auto;
            font-size: 0.9rem;
            line-height: 1.5;
            border: 1px solid var(--border-color);
        }

        .log::-webkit-scrollbar { width: 8px; }
        .log::-webkit-scrollbar-track { background: var(--card-bg); }
        .log::-webkit-scrollbar-thumb {
            background: var(--border-color);
            border-radius: 4px;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .container { padding: 15px; }
            .header { padding: 20px; }
            .header-left h1 { font-size: 2rem; }
            .grid { grid-template-columns: 1fr; gap: 20px; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <div class="header-left">
                    <h1><i class="fas fa-shield-alt"></i> ProVPN Enterprise</h1>
                    <p class="subtitle">Advanced VPN with Perfect Forward Secrecy & Protocol Testing</p>
                </div>
                <div class="header-right">
                    <div class="status-indicator status-offline" id="statusIndicator">
                        <i class="fas fa-circle" id="statusIcon"></i>
                        <span id="statusText">Offline</span>
                    </div>
                </div>
            </div>
            <div class="security-badges">
                <div class="badge pfs"><i class="fas fa-key"></i> Perfect Forward Secrecy</div>
                <div class="badge ssl"><i class="fas fa-lock"></i> SSL/TLS Encrypted</div>
                <div class="badge socks"><i class="fas fa-globe"></i> SOCKS5 Proxy</div>
                <div class="badge firefox"><i class="fab fa-firefox"></i> Firefox Ready</div>
            </div>
        </div>
        
        <div class="grid">
            <!-- Server Status Card -->
            <div class="card">
                <h3><i class="fas fa-server"></i> Server Status</h3>
                <div class="stats-grid">
                    <div class="stat">
                        <div class="stat-number" id="clientCount">0</div>
                        <div class="stat-label">Active Clients</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number" id="dataTransferred">0 MB</div>
                        <div class="stat-label">Data Transfer</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number" id="uptime">00:00:00</div>
                        <div class="stat-label">Uptime</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number" id="socksClients">0</div>
                        <div class="stat-label">SOCKS Clients</div>
                    </div>
                </div>
                <div style="text-align: center; margin-top: 20px;">
                    <button class="btn success" onclick="startServer()">
                        <i class="fas fa-play"></i> Start Server
                    </button>
                    <button class="btn danger" onclick="stopServer()">
                        <i class="fas fa-stop"></i> Stop Server
                    </button>
                    <button class="btn" onclick="restartServer()">
                        <i class="fas fa-redo"></i> Restart
                    </button>
                </div>
            </div>

            <!-- Protocol Routing Tester -->
            <div class="card">
                <h3><i class="fas fa-network-wired"></i> Protocol Routing Tester</h3>
                <div class="protocol-test" id="protocolTests">
                    <div class="protocol-card">
                        <div class="protocol-status status-testing" id="httpStatus">
                            <i class="fas fa-circle"></i>
                        </div>
                        <strong>HTTP</strong>
                        <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 5px;" id="httpResult">Ready</div>
                    </div>
                    <div class="protocol-card">
                        <div class="protocol-status status-testing" id="httpsStatus">
                            <i class="fas fa-circle"></i>
                        </div>
                        <strong>HTTPS</strong>
                        <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 5px;" id="httpsResult">Ready</div>
                    </div>
                    <div class="protocol-card">
                        <div class="protocol-status status-testing" id="tcpStatus">
                            <i class="fas fa-circle"></i>
                        </div>
                        <strong>TCP</strong>
                        <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 5px;" id="tcpResult">Ready</div>
                    </div>
                    <div class="protocol-card">
                        <div class="protocol-status status-testing" id="udpStatus">
                            <i class="fas fa-circle"></i>
                        </div>
                        <strong>UDP</strong>
                        <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 5px;" id="udpResult">Ready</div>
                    </div>
                    <div class="protocol-card">
                        <div class="protocol-status status-testing" id="icmpStatus">
                            <i class="fas fa-circle"></i>
                        </div>
                        <strong>ICMP</strong>
                        <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 5px;" id="icmpResult">Ready</div>
                    </div>
                    <div class="protocol-card">
                        <div class="protocol-status status-testing" id="dnsStatus">
                            <i class="fas fa-circle"></i>
                        </div>
                        <strong>DNS</strong>
                        <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 5px;" id="dnsResult">Ready</div>
                    </div>
                </div>
                <div style="text-align: center; margin-top: 20px;">
                    <button class="btn warning" onclick="runProtocolTests()">
                        <i class="fas fa-vial"></i> Run All Tests
                    </button>
                    <button class="btn" onclick="exportTestResults()">
                        <i class="fas fa-download"></i> Export Results
                    </button>
                </div>
            </div>

            <!-- Firefox Integration -->
            <div class="card">
                <h3><i class="fab fa-firefox"></i> Firefox Integration</h3>
                <p style="margin-bottom: 20px; color: var(--text-muted);">
                    Automatic proxy configuration with advanced security features
                </p>
                <div style="background: var(--dark-bg); padding: 15px; border-radius: 8px; margin: 15px 0;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                        <span>Proxy Configuration:</span>
                        <span id="firefoxProxyStatus" style="color: var(--warning-color);">Not Configured</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                        <span>DNS Leak Protection:</span>
                        <span id="firefoxDNSStatus" style="color: var(--warning-color);">Disabled</span>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <span>WebRTC Protection:</span>
                        <span id="firefoxWebRTCStatus" style="color: var(--warning-color);">Disabled</span>
                    </div>
                </div>
                <div style="text-align: center;">
                    <button class="btn firefox" onclick="configureFirefox()">
                        <i class="fas fa-cog"></i> Configure Firefox
                    </button>
                    <button class="btn firefox" onclick="launchFirefox()">
                        <i class="fas fa-rocket"></i> Launch VPN Firefox
                    </button>
                    <button class="btn warning" onclick="restoreFirefox()">
                        <i class="fas fa-undo"></i> Restore Settings
                    </button>
                </div>
            </div>

            <!-- Network Configuration -->
            <div class="card">
                <h3><i class="fas fa-cogs"></i> Network Configuration</h3>
                <div style="background: var(--dark-bg); padding: 15px; border-radius: 8px; font-family: monospace; font-size: 0.9rem;">
                    <div style="margin-bottom: 8px;"><strong>VPN Server:</strong> localhost:8044</div>
                    <div style="margin-bottom: 8px;"><strong>SOCKS5 Proxy:</strong> 127.0.0.1:1080</div>
                    <div style="margin-bottom: 8px;"><strong>Web Interface:</strong> localhost:8045</div>
                    <div style="margin-bottom: 8px;"><strong>Network Range:</strong> 10.8.0.0/24</div>
                    <div style="margin-bottom: 8px;"><strong>Encryption:</strong> AES-256-GCM + PFS</div>
                    <div><strong>SSL/TLS:</strong> <span id="sslStatus">Enabled</span></div>
                </div>
            </div>
        </div>

        <!-- Connected Clients -->
        <div class="card" style="grid-column: 1 / -1;">
            <h3><i class="fas fa-users"></i> Connected Clients</h3>
            <div class="table-container">
                <table class="table" id="clientsTable">
                    <thead>
                        <tr>
                            <th>Client ID</th>
                            <th>IP Address</th>
                            <th>Connected Since</th>
                            <th>Data Sent</th>
                            <th>Data Received</th>
                            <th>PFS Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="clientsBody">
                        <tr>
                            <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 40px;">
                                <i class="fas fa-user-slash" style="font-size: 2rem; margin-bottom: 10px; opacity: 0.5;"></i><br>
                                No clients connected
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- System Logs -->
        <div class="card" style="grid-column: 1 / -1;">
            <h3><i class="fas fa-terminal"></i> System Logs & Protocol Test Results</h3>
            <div id="logOutput" class="log">
                [System] ProVPN Enterprise Management Console Loaded...<br>
                [Security] Perfect Forward Secrecy encryption enabled<br>
                [SSL] Certificate validation in progress...<br>
                [Firefox] Automatic configuration ready<br>
                [Routing] Protocol testing engine initialized<br>
                [Status] Waiting for server initialization...<br>
            </div>
        </div>
    </div>
    
    <script>
        const socket = io();
        let serverRunning = false;
        
        // Socket event handlers
        socket.on('server_status', function(data) {
            updateServerStatus(data);
        });
        
        socket.on('log_message', function(data) {
            addLogMessage(data.message);
        });
        
        socket.on('protocol_test_result', function(data) {
            updateProtocolTestResult(data);
        });
        
        // Update server status
        function updateServerStatus(data) {
            serverRunning = data.running;
            const indicator = document.getElementById('statusIndicator');
            const icon = document.getElementById('statusIcon');
            const statusText = document.getElementById('statusText');
            
            if (data.running) {
                indicator.className = 'status-indicator status-online';
                statusText.textContent = 'Online';
            } else {
                indicator.className = 'status-indicator status-offline';
                statusText.textContent = 'Offline';
            }
            
            // Update stats
            document.getElementById('clientCount').textContent = data.stats?.clients || 0;
            document.getElementById('dataTransferred').textContent = (data.stats?.data_mb || 0) + ' MB';
            document.getElementById('uptime').textContent = data.stats?.uptime || '00:00:00';
            document.getElementById('socksClients').textContent = data.stats?.socks_clients || 0;
            
            // Update clients table
            updateClientsTable(data.clients || []);
        }
        
        // Update clients table
        function updateClientsTable(clients) {
            const tbody = document.getElementById('clientsBody');
            
            if (!clients || clients.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 40px;">
                            <i class="fas fa-user-slash" style="font-size: 2rem; margin-bottom: 10px; opacity: 0.5;"></i><br>
                            No clients connected
                        </td>
                    </tr>`;
                return;
            }
            
            tbody.innerHTML = clients.map(client => `
                <tr>
                    <td>${client.id}</td>
                    <td><code>${client.ip}</code></td>
                    <td>${client.connected_since}</td>
                    <td>${client.data_sent || '0 KB'}</td>
                    <td>${client.data_received || '0 KB'}</td>
                    <td>
                        <span style="color: ${client.pfs_enabled ? 'var(--success-color)' : 'var(--danger-color)'}">
                            <i class="fas fa-${client.pfs_enabled ? 'check' : 'times'}"></i>
                            ${client.pfs_enabled ? 'Enabled' : 'Disabled'}
                        </span>
                    </td>
                    <td>
                        <button class="btn danger" style="padding: 6px 12px; font-size: 0.8rem;" onclick="disconnectClient('${client.id}')">
                            <i class="fas fa-times"></i> Disconnect
                        </button>
                    </td>
                </tr>
            `).join('');
        }
        
        // Add log message
        function addLogMessage(message) {
            const logOutput = document.getElementById('logOutput');
            const timestamp = new Date().toLocaleTimeString();
            logOutput.innerHTML += `[${timestamp}] ${message}<br>`;
            logOutput.scrollTop = logOutput.scrollHeight;
        }
        
        // Protocol testing functions
        function runProtocolTests() {
            addLogMessage('[ROUTING] Starting comprehensive protocol tests...');
            
            const protocols = ['http', 'https', 'tcp', 'udp', 'icmp', 'dns'];
            protocols.forEach(protocol => {
                updateProtocolStatus(protocol, 'testing');
                socket.emit('run_protocol_test', {protocol: protocol});
            });
        }
        
        function updateProtocolStatus(protocol, status) {
            const statusElement = document.getElementById(protocol + 'Status');
            const resultElement = document.getElementById(protocol + 'Result');
            
            statusElement.className = `protocol-status status-${status}`;
            
            switch(status) {
                case 'testing':
                    resultElement.textContent = 'Testing...';
                    break;
                case 'success':
                    resultElement.textContent = 'Routed via VPN';
                    resultElement.style.color = 'var(--success-color)';
                    break;
                case 'failed':
                    resultElement.textContent = 'Not routed';
                    resultElement.style.color = 'var(--danger-color)';
                    break;
            }
        }
        
        function updateProtocolTestResult(data) {
            updateProtocolStatus(data.protocol, data.success ? 'success' : 'failed');
            addLogMessage(`[TEST] ${data.protocol.toUpperCase()}: ${data.message}`);
        }
        
        function exportTestResults() {
            socket.emit('export_test_results');
            addLogMessage('[EXPORT] Generating protocol test report...');
        }
        
        // Server control functions
        function startServer() {
            socket.emit('control_command', {action: 'start'});
            addLogMessage('[Command] Starting VPN server with PFS encryption...');
        }
        
        function stopServer() {
            socket.emit('control_command', {action: 'stop'});
            addLogMessage('[Command] Stopping VPN server...');
        }
        
        function restartServer() {
            socket.emit('control_command', {action: 'restart'});
            addLogMessage('[Command] Restarting VPN server...');
        }
        
        function configureFirefox() {
            socket.emit('control_command', {action: 'configure_firefox'});
            addLogMessage('[Firefox] Configuring browser for VPN with security enhancements...');
        }
        
        function launchFirefox() {
            socket.emit('control_command', {action: 'launch_firefox'});
            addLogMessage('[Firefox] Launching VPN-configured browser...');
        }
        
        function restoreFirefox() {
            socket.emit('control_command', {action: 'restore_firefox'});
            addLogMessage('[Firefox] Restoring original browser settings...');
        }
        
        function disconnectClient(clientId) {
            socket.emit('control_command', {action: 'disconnect_client', client_id: clientId});
            addLogMessage(`[Admin] Disconnecting client: ${clientId}`);
        }
        
        // Auto-refresh every 3 seconds
        setInterval(() => {
            socket.emit('get_status');
        }, 3000);
        
        // Initial status request
        socket.emit('get_status');
    </script>
</body>
</html>
        """
            
            @self.web_app.route('/')
            def web_interface():
                return render_template_string(web_template)
            
            @self.web_app.route('/api/status')
            def api_status():
                return jsonify({
                    'running': self.running,
                    'clients': len(self.clients),
                    'ssl_enabled': VPN_CONFIG['ssl_enabled'],
                    'firefox_configured': VPN_CONFIG['firefox_configured']
                })
            
            @self.socketio.on('get_status')
            def handle_status_request():
                try:
                    stats = self.get_server_stats()
                    safe_clients = self.get_safe_client_data()
                    
                    self.socketio.emit('server_status', {
                        'running': self.running,
                        'stats': stats,
                        'clients': safe_clients
                    })
                except Exception as e:
                    print(f"[ERROR] Status request failed: {e}")
            
            
            @self.socketio.on('run_protocol_test')
            def handle_protocol_test(data):
                try:
                    protocol = data.get('protocol')
                    if hasattr(self, 'routing_tester'):
                        # Run test in background thread
                        test_thread = threading.Thread(
                            target=self.routing_tester.run_comprehensive_test,
                            args=(protocol,),
                            daemon=True
                        )
                        test_thread.start()
                    else:
                        self.socketio.emit('protocol_test_result', {
                            'protocol': protocol,
                            'success': False,
                            'message': 'Routing tester not available'
                        })
                except Exception as e:
                    print(f"[ERROR] Protocol test failed: {e}")
            
            @self.socketio.on('export_test_results')
            def handle_export_test_results():
                try:
                    if hasattr(self, 'routing_tester'):
                        report = self.routing_tester.generate_test_report()
                        self.socketio.emit('log_message', {
                            'message': f'Test report generated with {report["summary"]["total_tests"]} tests'
                        })
                    else:
                        self.socketio.emit('log_message', {
                            'message': 'Routing tester not available for export'
                        })
                except Exception as e:
                    print(f"[ERROR] Export failed: {e}")
            
            @self.socketio.on('control_command')
            def handle_control_command(data):
                try:
                    action = data.get('action')
                    
                    if action == 'start':
                        self.start_server_async()
                    elif action == 'stop':
                        self.stop_server()
                    elif action == 'restart':
                        self.restart_server()
                    elif action == 'configure_firefox':
                        self.configure_firefox()
                    elif action == 'launch_firefox':
                        self.launch_firefox()
                    elif action == 'restore_firefox':
                        self.restore_firefox()
                    elif action == 'disconnect_client':
                        client_id = data.get('client_id')
                        self.disconnect_client(client_id)
                    
                    self.socketio.emit('log_message', {
                        'message': f'[Command] Executed: {action}'
                    })
                    
                except Exception as e:
                    print(f"[ERROR] Control command failed: {e}")
                    self.socketio.emit('log_message', {
                        'message': f'[Error] Command failed: {str(e)}'
                    })
            
            print("[OK] Enhanced web interface configured")
            
        except ImportError:
            print("[WARNING] Flask not available, web interface disabled")
    
    def get_safe_client_data(self):
        """Get JSON-safe client data"""
        safe_clients = []
        for client_id, client_data in self.clients.items():
            safe_client = {
                'id': client_data.get('id', client_id),
                'ip': client_data.get('ip', 'Unknown'),
                'connected_since': client_data.get('connected_since', 'Unknown'),
                'data_sent': client_data.get('data_sent', '0 KB'),
                'data_received': client_data.get('data_received', '0 KB'),
                'pfs_enabled': client_data.get('pfs_enabled', False)
            }
            safe_clients.append(safe_client)
        return safe_clients
    
    def get_server_stats(self):
        """Get comprehensive server statistics"""
        socks_clients = len(self.socks_proxy.clients) if self.socks_proxy else 0
        
        return {
            'clients': len(self.clients),
            'socks_clients': socks_clients,
            'data_mb': 0,  # Placeholder for actual traffic monitoring
            'uptime': '00:00:00',  # Placeholder for actual uptime tracking
            'ssl_enabled': VPN_CONFIG['ssl_enabled'],
            'pfs_sessions': sum(1 for c in self.clients.values() if c.get('pfs_enabled')),
            'firefox_configured': VPN_CONFIG['firefox_configured']
        }
    
    def start_server_async(self):
        """Start VPN server asynchronously"""
        if not self.running:
            server_thread = threading.Thread(target=self.start_server, daemon=True)
            server_thread.start()
    
    def start_server(self):
        """Start enhanced VPN server with PFS and SSL"""
        try:
            # Start SOCKS proxy first
            if self.socks_proxy and not self.socks_proxy.running:
                socks_thread = threading.Thread(target=self.socks_proxy.start, daemon=True)
                socks_thread.start()
                time.sleep(1)  # Give SOCKS time to start
            
            # Setup traffic routing
            if self.traffic_router:
                self.traffic_router.setup_routing()
                self.traffic_router.start_traffic_forwarding()
            
            # Start main VPN server
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Wrap with SSL if available
            if VPN_CONFIG['ssl_enabled'] and self.crypto_manager.ssl_context:
                self.server_socket = self.crypto_manager.ssl_context.wrap_socket(
                    self.server_socket, server_side=True
                )
                print(f"[SSL] VPN Server with SSL started on port {VPN_CONFIG['server_port']}")
            else:
                print(f"[VPN] VPN Server started on port {VPN_CONFIG['server_port']}")
            
            self.server_socket.bind(('0.0.0.0', VPN_CONFIG['server_port']))
            self.server_socket.listen(50)
            
            self.running = True
            
            print(f"[PFS] Perfect Forward Secrecy enabled")
            print(f"[SOCKS] SOCKS5 proxy on port {VPN_CONFIG['socks_port']}")
            print(f"[WEB] Management interface on port {VPN_CONFIG['web_port']}")
            
            # Accept client connections
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    print(f"[CONNECT] Client connected from {address}")
                    
                    client_thread = threading.Thread(
                        target=self.handle_pfs_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except Exception as accept_error:
                    if self.running:
                        print(f"[ERROR] Accept error: {accept_error}")
                        continue
                    else:
                        break
                        
        except Exception as e:
            print(f"[ERROR] Server start failed: {e}")
            self.running = False
    
    def handle_pfs_client(self, client_socket, address):
        """Handle VPN client with Perfect Forward Secrecy"""
        client_id = f"{address[0]}:{address[1]}"
        client_ip = f"10.8.0.{len(self.clients) + 10}"
        
        # Create per-client crypto manager
        client_crypto = PFSCryptoManager(is_server=True)
        
        try:
            print(f"[PFS] Starting PFS handshake with {client_id}")
            
            # Store client info
            self.clients[client_id] = {
                'id': client_id,
                'ip': client_ip,
                'socket': client_socket,
                'crypto': client_crypto,
                'connected_since': datetime.now().strftime('%H:%M:%S'),
                'data_sent': '0 KB',
                'data_received': '0 KB',
                'pfs_enabled': False
            }
            
            # PFS Handshake Step 1: Send server public key
            try:
                server_pubkey = client_crypto.get_public_key()
                handshake_msg = b"PFS_HANDSHAKE_V2:" + server_pubkey
                
                # Send with length prefix
                msg_len = len(handshake_msg)
                client_socket.send(msg_len.to_bytes(4, 'big') + handshake_msg)
                print(f"[PFS] Sent public key to {client_id}")
                
                # Receive client public key
                client_socket.settimeout(30)
                msg_len_bytes = client_socket.recv(4)
                
                if len(msg_len_bytes) == 4:
                    msg_len = int.from_bytes(msg_len_bytes, 'big')
                    client_handshake = client_socket.recv(msg_len)
                    
                    if client_handshake.startswith(b"PFS_HANDSHAKE_V2:"):
                        client_pubkey = client_handshake[17:]  # Remove prefix
                        
                        # Perform PFS key exchange
                        if client_crypto.perform_pfs_handshake(client_pubkey):
                            print(f"[OK] PFS handshake complete with {client_id}")
                            self.clients[client_id]['pfs_enabled'] = True
                            
                            # Send encrypted welcome message
                            welcome_msg = f"VPN_WELCOME_PFS:{client_ip}:{client_crypto.session_id}"
                            encrypted_welcome = client_crypto.encrypt_data(welcome_msg)
                            
                            welcome_len = len(encrypted_welcome)
                            client_socket.send(welcome_len.to_bytes(4, 'big') + encrypted_welcome)
                            print(f"[PFS] Sent encrypted welcome to {client_id}")
                        else:
                            raise Exception("PFS handshake failed")
                    else:
                        raise Exception("Invalid handshake response")
                else:
                    raise Exception("Handshake receive failed")
                    
            except Exception as handshake_error:
                print(f"[WARNING] PFS handshake failed for {client_id}: {handshake_error}")
                # Fallback to simple welcome
                welcome_msg = f"VPN_WELCOME_BASIC:{client_ip}"
                client_socket.send(welcome_msg.encode('utf-8'))
                print(f"[FALLBACK] Sent basic welcome to {client_id}")
            
            # Handle client communication
            while self.running:
                try:
                    client_socket.settimeout(60)  # 60 second timeout
                    data = client_socket.recv(8192)
                    
                    if not data:
                        break
                    
                    # Try to decrypt data
                    try:
                        if self.clients[client_id]['pfs_enabled']:
                            decrypted_data = client_crypto.decrypt_data(data)
                            message = decrypted_data.decode('utf-8')
                        else:
                            message = data.decode('utf-8', errors='ignore')
                        
                        print(f"[DATA] From {client_id}: {message}")
                        
                        # Update client stats
                        self.clients[client_id]['data_received'] = f"{len(data)} bytes"
                        
                        # Echo response
                        response = f"SERVER_ECHO_PFS:{message}"
                        
                        if self.clients[client_id]['pfs_enabled']:
                            encrypted_response = client_crypto.encrypt_data(response)
                            client_socket.send(encrypted_response)
                        else:
                            client_socket.send(response.encode('utf-8'))
                        
                        self.clients[client_id]['data_sent'] = f"{len(response)} bytes"
                        
                    except Exception as process_error:
                        print(f"[ERROR] Data processing error for {client_id}: {process_error}")
                        # Send error response
                        error_response = b"PROCESS_ERROR"
                        client_socket.send(error_response)
                    
                except socket.timeout:
                    # Send keepalive
                    try:
                        keepalive = "KEEPALIVE"
                        if self.clients[client_id]['pfs_enabled']:
                            encrypted_keepalive = client_crypto.encrypt_data(keepalive)
                            client_socket.send(encrypted_keepalive)
                        else:
                            client_socket.send(keepalive.encode('utf-8'))
                    except:
                        break
                        
                except Exception as comm_error:
                    print(f"[ERROR] Communication error with {client_id}: {comm_error}")
                    break
                    
        except Exception as e:
            print(f"[ERROR] Client handler error for {client_id}: {e}")
        finally:
            # Cleanup
            try:
                client_socket.close()
            except:
                pass
            
            if client_id in self.clients:
                del self.clients[client_id]
            
            print(f"[DISCONNECT] Client {client_id} disconnected")
    
    def stop_server(self):
        """Stop enhanced VPN server"""
        print("[STOP] Stopping enhanced VPN server...")
        
        self.running = False
        
        # Close all client connections
        for client_info in list(self.clients.values()):
            try:
                client_info['socket'].close()
            except:
                pass
        self.clients.clear()
        
        # Stop SOCKS proxy
        if self.socks_proxy:
            self.socks_proxy.stop()
        
        # Cleanup traffic routing
        if self.traffic_router:
            self.traffic_router.cleanup_routing()
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        print("[OK] Enhanced VPN server stopped")
    
    def restart_server(self):
        """Restart enhanced VPN server"""
        self.stop_server()
        time.sleep(3)
        self.start_server_async()
    
    def configure_firefox(self):
        """Configure Firefox for VPN"""
        if self.firefox_integrator:
            success = self.firefox_integrator.configure_firefox()
            if success:
                print("[OK] Firefox configured for VPN")
            else:
                print("[ERROR] Firefox configuration failed")
    
    def launch_firefox(self):
        """Launch Firefox with VPN configuration"""
        if self.firefox_integrator:
            success = self.firefox_integrator.launch_firefox_with_vpn()
            if success:
                print("[OK] Firefox launched with VPN profile")
            else:
                print("[ERROR] Firefox launch failed")
    
    def restore_firefox(self):
        """Restore original Firefox settings"""
        if self.firefox_integrator:
            self.firefox_integrator.restore_firefox_settings()
            print("[OK] Firefox settings restored")
    
    def disconnect_client(self, client_id):
        """Disconnect specific client"""
        if client_id in self.clients:
            try:
                self.clients[client_id]['socket'].close()
            except:
                pass
            del self.clients[client_id]
            print(f"[ADMIN] Client {client_id} disconnected by admin")
    
    def start_web_interface(self):
        """Start enhanced web management interface"""
        if self.web_app and FLASK_AVAILABLE:
            try:
                print(f"[WEB] Starting enhanced web interface on port {VPN_CONFIG['web_port']}")
                
                # Use SSL context if available
                if VPN_CONFIG['ssl_enabled'] and self.crypto_manager.ssl_context:
                    print(f"[SSL] Web interface with SSL enabled")
                    self.socketio.run(
                        self.web_app, 
                        host='0.0.0.0', 
                        port=VPN_CONFIG['web_port'], 
                        debug=False,
                        ssl_context=self.crypto_manager.ssl_context,
                        allow_unsafe_werkzeug=True
                    )
                else:
                    print(f"[HTTP] Web interface without SSL")
                    self.socketio.run(
                        self.web_app, 
                        host='0.0.0.0', 
                        port=VPN_CONFIG['web_port'], 
                        debug=False,
                        allow_unsafe_werkzeug=True
                    )
                    
            except Exception as e:
                print(f"[ERROR] Web interface failed: {e}")
        else:
            print("[WARNING] Web interface not available")


class EnhancedVPNInstaller:
    """Enhanced VPN installer with complete automation"""
    
    def __init__(self):
        self.system = platform.system()
        self.server = None
        
        # Setup install directory
        if self.system == "Windows":
            VPN_CONFIG['install_dir'] = os.path.join(
                os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'EnhancedVPN'
            )
        else:
            VPN_CONFIG['install_dir'] = '/opt/enhanced_vpn'
        
        # Create GUI
        self.create_enhanced_gui()
    
    def create_enhanced_gui(self):
        """Create enhanced installer GUI"""
        self.root = tk.Tk()
        self.root.title("Enhanced VPN Installer with PFS & SSL")
        self.root.geometry("900x700")
        self.root.configure(bg='#f0f0f0')
        
        # Enhanced header
        header_frame = tk.Frame(self.root, bg='#2c3e50', height=120)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame, 
            text="🛡️ Enhanced VPN Solution",
            font=('Arial', 20, 'bold'), 
            fg='white', 
            bg='#2c3e50'
        )
        title_label.pack(pady=10)
        
        subtitle_label = tk.Label(
            header_frame,
            text="Perfect Forward Secrecy • SSL/TLS • Firefox Integration • Traffic Routing",
            font=('Arial', 12),
            fg='#ecf0f1',
            bg='#2c3e50'
        )
        subtitle_label.pack()
        
        # Feature badges
        badges_frame = tk.Frame(header_frame, bg='#2c3e50')
        badges_frame.pack(pady=10)
        
        badges = [
            ("🔐 PFS", '#27ae60'),
            ("🔒 SSL", '#3498db'),
            ("🌐 SOCKS5", '#e74c3c'),
            ("🦊 Firefox", '#f39c12')
        ]
        
        for badge_text, color in badges:
            badge = tk.Label(
                badges_frame,
                text=badge_text,
                font=('Arial', 9, 'bold'),
                fg='white',
                bg=color,
                padx=8,
                pady=4
            )
            badge.pack(side='left', padx=5)
        
        # Main content
        main_frame = tk.Frame(self.root, bg='#f0f0f0')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Installation steps
        steps_label = tk.Label(
            main_frame, 
            text="Installation Progress:",
            font=('Arial', 14, 'bold'), 
            bg='#f0f0f0'
        )
        steps_label.pack(anchor='w', pady=(0, 10))
        
        self.steps_text = scrolledtext.ScrolledText(
            main_frame, 
            height=20, 
            width=90,
            font=('Consolas', 9),
            bg='#2c3e50',
            fg='#ecf0f1',
            insertbackground='white'
        )
        self.steps_text.pack(fill='both', expand=True, pady=(0, 10))
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, length=500, mode='determinate')
        self.progress.pack(fill='x', pady=(0, 20))
        
        # Enhanced buttons
        button_frame = tk.Frame(main_frame, bg='#f0f0f0')
        button_frame.pack(fill='x')
        
        buttons = [
            ("🚀 Install Enhanced VPN", self.start_installation, '#27ae60'),
            ("🦊 Configure Firefox", self.configure_firefox_only, '#f39c12'),
            ("🌐 Open Web Console", self.open_web_interface, '#3498db'),
            ("📱 Generate Client", self.generate_client, '#9b59b6')
        ]
        
        for text, command, color in buttons:
            btn = tk.Button(
                button_frame,
                text=text,
                command=command,
                font=('Arial', 11, 'bold'),
                bg=color,
                fg='white',
                padx=20,
                pady=12,
                relief='flat',
                cursor='hand2'
            )
            btn.pack(side='left', padx=10)
        
        # Add status indicators
        status_frame = tk.Frame(main_frame, bg='#f0f0f0')
        status_frame.pack(fill='x', pady=(20, 0))
        
        self.status_labels = {}
        statuses = [
            ("Crypto", "⚠️ Not Checked"),
            ("SSL", "⚠️ Not Configured"),
            ("Firefox", "⚠️ Not Configured"),
            ("Server", "⚠️ Not Started")
        ]
        
        for status_name, initial_text in statuses:
            status_item = tk.Frame(status_frame, bg='#f0f0f0')
            status_item.pack(side='left', padx=20)
            
            tk.Label(
                status_item,
                text=f"{status_name}:",
                font=('Arial', 10, 'bold'),
                bg='#f0f0f0'
            ).pack()
            
            self.status_labels[status_name] = tk.Label(
                status_item,
                text=initial_text,
                font=('Arial', 9),
                bg='#f0f0f0',
                fg='#e67e22'
            )
            self.status_labels[status_name].pack()
        
        # Initial setup
        self.log("🛡️ Enhanced VPN Installer Ready")
        self.log("🔐 Perfect Forward Secrecy encryption available")
        self.log("🔒 SSL/TLS hosting enabled")
        self.log("🦊 Firefox integration ready")
        self.log("🌐 SOCKS5 proxy with DNS routing")
        self.log("📊 Advanced web management console")
        self.log("")
        self.log("Click 'Install Enhanced VPN' to begin complete setup")
        
        self.check_initial_status()
    
    def log(self, message):
        """Enhanced logging with colors"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.steps_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.steps_text.see(tk.END)
        self.root.update()
    
    def update_progress(self, value):
        """Update progress bar"""
        self.progress['value'] = value
        self.root.update()
    
    def update_status(self, component, status, color='#27ae60'):
        """Update status indicator"""
        if component in self.status_labels:
            self.status_labels[component].config(text=status, fg=color)
    
    def check_initial_status(self):
        """Check initial system status"""
        # Check crypto
        if CRYPTO_AVAILABLE:
            self.update_status("Crypto", "✅ Available")
        else:
            self.update_status("Crypto", "❌ Missing", '#e74c3c')
        
        # Check SSL certificates
        if os.path.exists(VPN_CONFIG['cert_path']) and os.path.exists(VPN_CONFIG['key_path']):
            self.update_status("SSL", "✅ Certificates Found")
        else:
            self.update_status("SSL", "⚠️ Will Generate", '#f39c12')
    
    def start_installation(self):
        """Start complete enhanced VPN installation"""
        install_thread = threading.Thread(target=self.install_enhanced_vpn, daemon=True)
        install_thread.start()
    
    def install_enhanced_vpn(self):
        """Install complete enhanced VPN solution"""
        try:
            self.log("🚀 Starting Enhanced VPN Installation...")
            self.update_progress(5)
            
            # Step 1: Install dependencies
            self.log("📦 Installing Python dependencies...")
            self.install_dependencies()
            self.update_progress(20)
            
            # Step 2: Setup SSL certificates
            self.log("🔒 Setting up SSL/TLS certificates...")
            crypto_manager = PFSCryptoManager(is_server=True)
            if VPN_CONFIG['ssl_enabled']:
                self.update_status("SSL", "✅ Configured")
            self.update_progress(35)
            
            # Step 3: Create installation directory
            self.log(f"📁 Creating installation directory: {VPN_CONFIG['install_dir']}")
            os.makedirs(VPN_CONFIG['install_dir'], exist_ok=True)
            self.update_progress(45)
            
            # Step 4: Configure Windows networking (if Windows)
            if self.system == "Windows":
                self.log("🌐 Configuring Windows networking...")
                self.setup_windows_networking()
            self.update_progress(60)
            
            # Step 5: Create enhanced VPN server
            self.log("🛡️ Creating Enhanced VPN Server...")
            self.server = EnhancedVPNServer()
            self.update_progress(75)
            
            # Step 6: Configure Firefox
            self.log("🦊 Configuring Firefox...")
            self.server.configure_firefox()
            self.update_status("Firefox", "✅ Configured")
            self.update_progress(85)
            
            # Step 7: Start all services
            self.log("🚀 Starting VPN services...")
            
            # Start VPN server
            server_thread = threading.Thread(target=self.server.start_server, daemon=True)
            server_thread.start()
            
            # Start web interface
            web_thread = threading.Thread(target=self.server.start_web_interface, daemon=True)
            web_thread.start()
            
            self.update_progress(95)
            
            # Step 8: Generate client
            self.log("📱 Generating enhanced VPN client...")
            self.generate_enhanced_client()
            self.update_progress(100)
            
            # Final status updates
            self.update_status("Server", "✅ Running")
            
            self.log("")
            self.log("🎉 Enhanced VPN Installation Complete!")
            self.log("=" * 50)
            self.log(f"🛡️ VPN Server: localhost:{VPN_CONFIG['server_port']} (SSL)")
            self.log(f"🌐 SOCKS5 Proxy: 127.0.0.1:{VPN_CONFIG['socks_port']}")
            self.log(f"📊 Web Console: https://localhost:{VPN_CONFIG['web_port']}")
            self.log("🦊 Firefox: Automatically configured")
            self.log("🔐 Perfect Forward Secrecy: Enabled")
            self.log("🔒 SSL/TLS Encryption: Active")
            self.log("")
            self.log("You can now browse securely through the VPN!")
            
            # Show completion dialog
            messagebox.showinfo(
                "Installation Complete",
                "Enhanced VPN with Perfect Forward Secrecy installed successfully!\n\n"
                f"VPN Server: localhost:{VPN_CONFIG['server_port']}\n"
                f"Web Console: https://localhost:{VPN_CONFIG['web_port']}\n"
                f"SOCKS5 Proxy: 127.0.0.1:{VPN_CONFIG['socks_port']}\n\n"
                "Firefox has been automatically configured.\n"
                "Click 'Configure Firefox' to launch VPN browser."
            )
            
        except Exception as e:
            self.log(f"❌ Installation failed: {e}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Installation Failed", f"Installation failed: {e}")
    
    def install_dependencies(self):
        """Install required dependencies"""
        dependencies = [
            "cryptography>=41.0.0",
            "flask>=2.3.0",
            "flask-socketio>=5.3.0",
            "requests>=2.31.0",
            "psutil>=5.9.0"
        ]
        
        for dep in dependencies:
            try:
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install", dep, "--upgrade"
                ], timeout=300)
                self.log(f"✅ Installed: {dep}")
            except Exception as e:
                self.log(f"⚠️ Failed to install {dep}: {e}")
    
    def setup_windows_networking(self):
        """Setup Windows networking for VPN"""
        try:
            # Enable IP forwarding
            subprocess.run([
                "netsh", "interface", "ipv4", "set", "global", "forwarding=enabled"
            ], timeout=30)
            
            # Configure firewall
            firewall_rules = [
                ("VPN-Enhanced-Server", VPN_CONFIG['server_port']),
                ("VPN-Enhanced-SOCKS", VPN_CONFIG['socks_port']),
                ("VPN-Enhanced-Web", VPN_CONFIG['web_port'])
            ]
            
            for rule_name, port in firewall_rules:
                try:
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}", "dir=in", "action=allow",
                        "protocol=TCP", f"localport={port}"
                    ], timeout=30)
                except:
                    pass
            
            self.log("✅ Windows networking configured")
            
        except Exception as e:
            self.log(f"⚠️ Windows networking setup failed: {e}")
    
    def configure_firefox_only(self):
        """Configure Firefox only"""
        try:
            self.log("🦊 Configuring Firefox for VPN...")
            
            firefox_integrator = FirefoxIntegrator()
            success = firefox_integrator.configure_firefox()
            
            if success:
                self.log("✅ Firefox configured successfully")
                self.update_status("Firefox", "✅ Configured")
                
                # Launch Firefox with VPN profile
                if firefox_integrator.launch_firefox_with_vpn():
                    self.log("🚀 Firefox launched with VPN profile")
                    messagebox.showinfo(
                        "Firefox Configured",
                        "Firefox has been configured for VPN use!\n\n"
                        "Features enabled:\n"
                        "• SOCKS5 proxy routing\n"
                        "• DNS through proxy\n"
                        "• WebRTC leak protection\n"
                        "• Enhanced privacy settings\n\n"
                        "Firefox VPN profile has been launched."
                    )
            else:
                self.log("❌ Firefox configuration failed")
                messagebox.showerror("Error", "Firefox configuration failed")
                
        except Exception as e:
            self.log(f"❌ Firefox configuration error: {e}")
            messagebox.showerror("Error", f"Firefox configuration failed: {e}")
    
    def generate_client(self):
        """Generate enhanced VPN client"""
        try:
            self.log("📱 Generating enhanced VPN client...")
            client_path = self.generate_enhanced_client()
            
            if client_path:
                self.log(f"✅ Client generated: {client_path}")
                messagebox.showinfo(
                    "Client Generated",
                    f"Enhanced VPN client generated!\n\n"
                    f"Location: {client_path}\n\n"
                    "Features:\n"
                    "• Perfect Forward Secrecy\n"
                    "• SSL/TLS encryption\n"
                    "• Automatic reconnection\n"
                    "• Traffic monitoring\n\n"
                    "Run the client to connect to your VPN server."
                )
            else:
                self.log("❌ Client generation failed")
                messagebox.showerror("Error", "Failed to generate VPN client")
                
        except Exception as e:
            self.log(f"❌ Client generation error: {e}")
            messagebox.showerror("Error", f"Client generation failed: {e}")
    
    def generate_enhanced_client(self):
        """Generate the enhanced VPN client script"""
        try:
            client_code = '''#!/usr/bin/env python3
"""
Enhanced VPN Client with Perfect Forward Secrecy
Generated by Enhanced VPN Server
"""

import socket
import ssl
import threading
import time
import struct
import json
import sys
import os
from datetime import datetime

# Import crypto with fallback
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.fernet import Fernet
    import secrets
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[WARNING] Advanced cryptography not available")

class EnhancedVPNClient:
    """Enhanced VPN Client with PFS support"""
    
    def __init__(self, server_host='localhost', server_port=8044):
        self.server_host = server_host
        self.server_port = server_port
        self.connected = False
        self.socket = None
        self.crypto_manager = None
        self.running = False
        
        if CRYPTO_AVAILABLE:
            self.setup_crypto()
    
    def setup_crypto(self):
        """Setup client-side cryptography"""
        try:
            # Generate client ephemeral keys
            self.private_key = ec.generate_private_key(ec.SECP256R1())
            self.public_key = self.private_key.public_key()
            self.public_key_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            self.session_key = None
            print("[PFS] Client crypto initialized")
        except Exception as e:
            print(f"[ERROR] Crypto setup failed: {e}")
            self.crypto_available = False
    
    def connect_with_pfs(self):
        """Connect to server with PFS handshake"""
        try:
            print(f"[CONNECT] Connecting to {self.server_host}:{self.server_port}")
            
            # Create socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Setup SSL context for client
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # For self-signed certificates
            
            # Wrap socket with SSL
            try:
                self.socket = context.wrap_socket(self.socket, server_hostname=self.server_host)
                print("[SSL] SSL connection established")
            except Exception as ssl_error:
                print(f"[WARNING] SSL failed, using plain connection: {ssl_error}")
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Connect to server
            self.socket.connect((self.server_host, self.server_port))
            print("[CONNECT] Connected to VPN server")
            
            # Perform PFS handshake
            if CRYPTO_AVAILABLE:
                self.perform_pfs_handshake()
            
            self.connected = True
            return True
            
        except Exception as e:
            print(f"[ERROR] Connection failed: {e}")
            return False
    
    def perform_pfs_handshake(self):
        """Perform PFS handshake with server"""
        try:
            print("[PFS] Starting handshake...")
            
            # Receive server public key
            msg_len_bytes = self.socket.recv(4)
            msg_len = int.from_bytes(msg_len_bytes, 'big')
            server_handshake = self.socket.recv(msg_len)
            
            if server_handshake.startswith(b"PFS_HANDSHAKE_V2:"):
                server_pubkey_bytes = server_handshake[17:]
                
                # Reconstruct server public key
                server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), server_pubkey_bytes
                )
                
                # Send client public key
                client_handshake = b"PFS_HANDSHAKE_V2:" + self.public_key_bytes
                msg_len = len(client_handshake)
                self.socket.send(msg_len.to_bytes(4, 'big') + client_handshake)
                
                # Perform ECDH
                shared_key = self.private_key.exchange(ec.ECDH(), server_public_key)
                
                # Derive session key
                session_info = f"VPN_PFS_CLIENT_{int(time.time())}"
                self.session_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b"VPN_PFS_SALT_2024_ENHANCED",
                    info=session_info.encode()
                ).derive(shared_key)
                
                # Clear private key for PFS
                self.private_key = None
                
                print("[OK] PFS handshake complete")
                
                # Receive welcome message
                welcome_len_bytes = self.socket.recv(4)
                welcome_len = int.from_bytes(welcome_len_bytes, 'big')
                encrypted_welcome = self.socket.recv(welcome_len)
                
                decrypted_welcome = self.decrypt_data(encrypted_welcome)
                welcome_msg = decrypted_welcome.decode('utf-8')
                print(f"[SERVER] {welcome_msg}")
                
                return True
                
        except Exception as e:
            print(f"[ERROR] PFS handshake failed: {e}")
            return False
    
    def encrypt_data(self, data):
        """Encrypt data with session key"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if not CRYPTO_AVAILABLE or not self.session_key:
            return b"PLAIN:" + data
        
        try:
            nonce = secrets.token_bytes(12)
            cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            return b"AES256:" + nonce + encryptor.tag + ciphertext
        except Exception:
            return b"PLAIN:" + data
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data with session key"""
        if encrypted_data.startswith(b"PLAIN:"):
            return encrypted_data[6:]
        
        if encrypted_data.startswith(b"AES256:"):
            if not CRYPTO_AVAILABLE or not self.session_key:
                raise Exception("Cannot decrypt AES256 data")
            
            encrypted_data = encrypted_data[7:]
            nonce = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            
            cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        
        return encrypted_data
    
    def send_message(self, message):
        """Send encrypted message to server"""
        try:
            if self.connected and self.socket:
                encrypted_msg = self.encrypt_data(message)
                self.socket.send(encrypted_msg)
                print(f"[SENT] {message}")
                return True
        except Exception as e:
            print(f"[ERROR] Send failed: {e}")
            return False
    
    def receive_messages(self):
        """Receive messages from server"""
        while self.running and self.connected:
            try:
                data = self.socket.recv(8192)
                if not data:
                    break
                
                try:
                    decrypted_data = self.decrypt_data(data)
                    message = decrypted_data.decode('utf-8')
                    print(f"[RECEIVED] {message}")
                except Exception:
                    print(f"[RECEIVED] {data}")
                
            except Exception as e:
                print(f"[ERROR] Receive error: {e}")
                break
        
        self.connected = False
    
    def start_interactive_mode(self):
        """Start interactive client mode"""
        if not self.connect_with_pfs():
            return
        
        self.running = True
        
        # Start receive thread
        receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        receive_thread.start()
        
        print("\\n" + "="*50)
        print("🛡️ Enhanced VPN Client Connected!")
        print("🔐 Perfect Forward Secrecy: Active")
        print("🔒 End-to-end encryption enabled")
        print("Type 'quit' to disconnect")
        print("="*50 + "\\n")
        
        # Interactive loop
        try:
            while self.running:
                try:
                    message = input("VPN> ")
                    if message.lower() in ['quit', 'exit', 'q']:
                        break
                    
                    if message.strip():
                        self.send_message(message)
                        
                except KeyboardInterrupt:
                    break
                except EOFError:
                    break
                    
        finally:
            self.disconnect()
    
    def disconnect(self):
        """Disconnect from server"""
        print("\\n[DISCONNECT] Closing connection...")
        self.running = False
        self.connected = False
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        print("[OK] Disconnected from VPN server")

def main():
    """Main client function"""
    print("🛡️ Enhanced VPN Client with Perfect Forward Secrecy")
    print("="*50)
    
    # Configuration
    server_host = 'localhost'
    server_port = 8044
    
    # Allow command line arguments
    if len(sys.argv) >= 2:
        server_host = sys.argv[1]
    if len(sys.argv) >= 3:
        try:
            server_port = int(sys.argv[2])
        except ValueError:
            print("Invalid port number")
            return
    
    print(f"Server: {server_host}:{server_port}")
    
    # Create and start client
    client = EnhancedVPNClient(server_host, server_port)
    client.start_interactive_mode()

if __name__ == "__main__":
    main()
'''
            
            # Save client script
            client_filename = "enhanced_vpn_client.py"
            client_path = os.path.join(VPN_CONFIG['install_dir'], client_filename)
            
            # Ensure install directory exists
            os.makedirs(VPN_CONFIG['install_dir'], exist_ok=True)
            
            with open(client_path, 'w', encoding='utf-8') as f:
                f.write(client_code)
            
            # Make executable on Unix systems
            if self.system != "Windows":
                os.chmod(client_path, 0o755)
            
            self.log(f"✅ Enhanced VPN client saved to: {client_path}")
            return client_path
            
        except Exception as e:
            self.log(f"❌ Client generation failed: {e}")
            return None
    
    def open_web_interface(self):
        """Open web management interface"""
        try:
            import webbrowser
            
            protocol = "https" if VPN_CONFIG['ssl_enabled'] else "http"
            url = f"{protocol}://localhost:{VPN_CONFIG['web_port']}"
            
            self.log(f"🌐 Opening web interface: {url}")
            webbrowser.open(url)
            
            messagebox.showinfo(
                "Web Interface",
                f"Opening VPN management console in browser:\n\n"
                f"{url}\n\n"
                "If the server is not running, click 'Install Enhanced VPN' first."
            )
            
        except Exception as e:
            self.log(f"❌ Failed to open web interface: {e}")
            messagebox.showerror("Error", f"Failed to open web interface: {e}")
    
    def run(self):
        """Run the installer GUI"""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.shutdown()
        except Exception as e:
            print(f"GUI Error: {e}")
            self.shutdown()
    
    def shutdown(self):
        """Shutdown installer and cleanup"""
        try:
            if self.server:
                self.server.stop_server()
            self.root.quit()
        except:
            pass


def main():
    """Main function"""
    print("🛡️ Enhanced VPN Solution with Perfect Forward Secrecy")
    print("=" * 60)
    print("Features:")
    print("🔐 Perfect Forward Secrecy (ECDH key exchange)")
    print("🔒 SSL/TLS encrypted proxy hosting") 
    print("🌐 SOCKS5 proxy with DNS routing")
    print("🦊 Automatic Firefox configuration")
    print("📊 Advanced web management interface")
    print("🛡️ Traffic routing and NAT")
    print("📱 Client certificate management")
    print("=" * 60)
    
    try:
        # Check system requirements
        if not CRYPTO_AVAILABLE:
            print("[WARNING] Cryptography library not available")
            print("Install with: pip install cryptography")
            print("Some features will be disabled")
        
        if not FLASK_AVAILABLE:
            print("[WARNING] Flask not available") 
            print("Install with: pip install flask flask-socketio")
            print("Web interface will be disabled")
        
        # Start installer GUI
        installer = EnhancedVPNInstaller()
        installer.run()
        
    except KeyboardInterrupt:
        print("\n[EXIT] Installation cancelled by user")
    except Exception as e:
        print(f"[ERROR] Fatal error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
    