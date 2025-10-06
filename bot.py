#!/usr/bin/env python3
import logging
import socket
import ssl
import concurrent.futures
import os
import time
import datetime
from urllib.parse import urlparse
from typing import List, Tuple, Dict
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler, filters, 
    CallbackContext, CallbackQueryHandler
)
from flask import Flask, jsonify
import threading
import requests

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# Bot Configuration - MUST be set in environment variables on Render
BOT_TOKEN = os.environ.get('BOT_TOKEN')
OWNER_CHAT_ID = os.environ.get('OWNER_CHAT_ID')

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN environment variable is required")

# Channel links - Users must join these for premium access
CHANNELS = [
    {"name": "🔥 CHANNEL 1", "url": "https://t.me/redsmoker2", "id": "@redsmoker2"},
    {"name": "🔥 CHANNEL 2", "url": "https://t.me/redsmoker1", "id": "@redsmoker1"},
    {"name": "🔥 CHANNEL 3", "url": "https://t.me/redsmoker0", "id": "@redsmoker0"}
]

# Rate Limiting Configuration
MAX_USERS_PER_HOUR = 100
MAX_REQUESTS_FREE = 3
MAX_REQUESTS_PREMIUM = 5
REQUEST_RESET_HOURS = 24

# User Management
user_sessions = {}
user_requests = {}
user_join_times = {}
hourly_users = {}

# --- Color Panel for Scanner ---
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'

# Flask app for health checks
app = Flask(__name__)

# Global variable to track bot status
bot_running = False
application = None

@app.route('/')
def health_check():
    bot_status = "running" if bot_running else "stopped"
    return jsonify({
        "status": "healthy", 
        "service": "Telegram Bot",
        "bot_status": bot_status,
        "timestamp": datetime.datetime.now().isoformat()
    })

@app.route('/health')
def health():
    return jsonify({
        "status": "healthy", 
        "timestamp": datetime.datetime.now().isoformat()
    })

@app.route('/start_bot', methods=['POST'])
def start_bot():
    global bot_running, application
    if not bot_running:
        threading.Thread(target=run_bot, daemon=True).start()
        return jsonify({"status": "starting", "message": "Bot is starting..."})
    return jsonify({"status": "already_running", "message": "Bot is already running"})

@app.route('/stop_bot', methods=['POST'])
def stop_bot():
    global bot_running, application
    if bot_running and application:
        application.stop()
        bot_running = False
        return jsonify({"status": "stopping", "message": "Bot is stopping..."})
    return jsonify({"status": "not_running", "message": "Bot is not running"})

class UserManager:
    """Manage user access, rate limiting, and channel verification"""
    
    @staticmethod
    def can_user_access(user_id: int) -> Tuple[bool, str]:
        """Check if user can access the bot with rate limiting"""
        current_hour = int(time.time() // 3600)
        
        # Clean old hourly data
        for hour in list(hourly_users.keys()):
            if hour < current_hour - 1:  # Keep only current and previous hour
                del hourly_users[hour]
        
        # Check hourly user limit
        if current_hour not in hourly_users:
            hourly_users[current_hour] = set()
        
        if len(hourly_users[current_hour]) >= MAX_USERS_PER_HOUR:
            return False, f"❌ Bot is currently at capacity. Please try again in the next hour. (Max {MAX_USERS_PER_HOUR} users/hour)"
        
        # Add user to current hour
        hourly_users[current_hour].add(user_id)
        return True, ""
    
    @staticmethod
    def can_make_request(user_id: int, context: CallbackContext) -> Tuple[bool, str, int]:
        """Check if user can make a scan request"""
        now = time.time()
        
        # Initialize user request data
        if user_id not in user_requests:
            user_requests[user_id] = {
                'count': 0,
                'last_reset': now,
                'joined_channels': False
            }
        
        user_data = user_requests[user_id]
        
        # Reset daily counter if 24 hours passed
        if now - user_data['last_reset'] >= REQUEST_RESET_HOURS * 3600:
            user_data['count'] = 0
            user_data['last_reset'] = now
        
        max_requests = MAX_REQUESTS_PREMIUM if user_data['joined_channels'] else MAX_REQUESTS_FREE
        remaining = max_requests - user_data['count']
        
        if user_data['count'] >= max_requests:
            reset_time = user_data['last_reset'] + (REQUEST_RESET_HOURS * 3600)
            time_left = reset_time - now
            hours_left = int(time_left // 3600)
            minutes_left = int((time_left % 3600) // 60)
            
            if user_data['joined_channels']:
                return False, f"❌ You've used all {MAX_REQUESTS_PREMIUM} daily requests. Reset in {hours_left}h {minutes_left}m", remaining
            else:
                message = (
                    f"❌ You've used all {MAX_REQUESTS_FREE} free daily requests.\n\n"
                    f"**Join our channels to get {MAX_REQUESTS_PREMIUM} requests per day!**\n"
                    f"Use /channels to join and then /verify to check membership."
                )
                return False, message, remaining
        
        return True, f"✅ Requests today: {user_data['count']}/{max_requests}", remaining
    
    @staticmethod
    def increment_request_count(user_id: int):
        """Increment user's request count"""
        if user_id not in user_requests:
            user_requests[user_id] = {
                'count': 1,
                'last_reset': time.time(),
                'joined_channels': False
            }
        else:
            user_requests[user_id]['count'] += 1
    
    @staticmethod
    async def check_channel_membership(user_id: int, context: CallbackContext) -> bool:
        """Check if user has joined all required channels"""
        try:
            for channel in CHANNELS:
                member = await context.bot.get_chat_member(chat_id=channel['id'], user_id=user_id)
                if member.status in ['left', 'kicked', 'banned']:
                    return False
            
            # Update user status if they joined all channels
            if user_id in user_requests:
                user_requests[user_id]['joined_channels'] = True
            return True
        except Exception as e:
            logging.error(f"Error checking channel membership for {user_id}: {e}")
            return False

class NetworkScanner:
    def __init__(self, protocol: str, hosts_file: str):
        """
        Initializes scanner with the specified protocol and hosts file.

        Args:
            protocol (str): The protocol to use ('http', 'tls', or 'vless').
            hosts_file (str): The name of the file containing host addresses.
        """
        # --- FEATURE: User file specification & Log file change ---
        self.hosts_file = hosts_file
        self.max_workers = 30
        self.connect_timeout = 10
        self.rate_limit_delay = 0.1  # seconds per request
        self.success_log_file = 'Host_File.txt' # FEATURE: Successful host log

        self.protocol = protocol.lower()
        self.ssl_context = None
        self.success_response = ''
        self.server_hostname = None
        self.vless_path = None
        self.port = 443 # Default port

        if self.protocol == 'tls':
            self.success_response = 'HTTP/1.1 101 Switching Protocols'
            self.ssl_context = self._create_ssl_context()
            self.server_hostname = 'nl1.wstunnel.xyz'
            print(f"{BLUE}Scanner configured for TLS on port {self.port}.{RESET}")
        
        elif self.protocol == 'http':
            self.success_response = 'HTTP/1.1 200 OK'
            print(f"{BLUE}Scanner configured for HTTP on port {self.port}.{RESET}")

        elif self.protocol == 'vless':
            self.success_response = 'HTTP/1.1 101 Switching Protocols'
            self.ssl_context = self._create_ssl_context()
            self.server_hostname = 'sa3.vpnjantit.com'
            self.vless_path = '/vpnjantit'
            print(f"{BLUE}Scanner configured for VLESS over TLS on port {self.port}.{RESET}")

        else:
            raise ValueError("Unsupported protocol. Choose 'http', 'tls', or 'vless'.")

    def _create_ssl_context(self):
        """Create custom SSL context with relaxed verification for TLS/SSL."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def _generate_handshake(self, host: str) -> bytes:
        """Generate handshake payload for the chosen protocol."""
        host_header = self.server_hostname if self.server_hostname else host
        
        if self.protocol in ['tls', 'vless']:
            path = self.vless_path if self.protocol == 'vless' else '/'
            return (
                f'GET {path} HTTP/1.1\r\n'
                f'Host: {host_header}\r\n'
                f'Upgrade: websocket\r\n'
                f'Connection: Upgrade\r\n'
                f'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
                f'Sec-WebSocket-Version: 13\r\n'
                f'\r\n'
            ).encode('utf-8')
        
        elif self.protocol == 'http':
            return (
                f'GET / HTTP/1.1\r\n'
                f'Host: {host}\r\n'
                f'Connection: close\r\n'
                f'\r\n'
            ).encode('utf-8')
        
        return b''

    def _log_successful_host(self, host: str):
        """Log a successful host to the Host_File.txt log file."""
        try:
            with open(self.success_log_file, 'a') as log_file:
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                log_file.write(f"{timestamp} - {self.protocol.upper()}://{host}:{self.port} (SNI: {self.server_hostname})\n")
        except IOError as e:
            print(f"{RED}[LOG ERROR]{RESET} Could not write to log file: {e}")

    def check_host(self, host: str) -> Tuple[str, bool]:
        """Check if a host responds with the expected protocol success message."""
        print(f'{CYAN}[CHECKING]{RESET} {host}:{self.port}...')
        time.sleep(self.rate_limit_delay)
        
        try:
            with socket.create_connection((host, self.port), timeout=self.connect_timeout) as sock:
                if self.protocol in ['tls', 'vless']:
                    sni_hostname = self.server_hostname if self.server_hostname else host
                    wrapped_sock = self.ssl_context.wrap_socket(sock, server_hostname=sni_hostname)
                    
                    with wrapped_sock as ssl_sock:
                        ssl_sock.sendall(self._generate_handshake(host))
                        response = ssl_sock.recv(4096).decode('utf-8', errors='ignore')
                else:
                    sock.sendall(self._generate_handshake(host))
                    response = sock.recv(4096).decode('utf-8', errors='ignore')

                # Improved response checking
                if self.protocol in ['tls', 'vless'] and response.startswith('HTTP/1.1 101 Switching Protocols'):
                    print(f'{GREEN}[SUCCESS]{RESET} {host}:{self.port} ({self.protocol.upper()} Tunnel Ready)')
                    self._log_successful_host(host)
                    return (host, True)
                
                elif self.protocol == 'http' and response.startswith(self.success_response):
                    print(f'{GREEN}[SUCCESS]{RESET} {host}:{self.port} (Expected Response: {self.success_response})')
                    self._log_successful_host(host)
                    return (host, True)
                    
                else:
                    error_line = response.splitlines()[0] if response else "No valid response header"
                    print(f'{YELLOW}[RESPONSE MISMATCH]{RESET} {host}:{self.port} - Expected: {self.success_response[:10]}... Got: {error_line[:60]}...')
                    return (host, False)
                        
        except socket.timeout:
            print(f'{RED}[TIMEOUT]{RESET} {host}:{self.port}')
            return (host, False)
        except (socket.error, ssl.SSLError, ConnectionRefusedError) as e:
            print(f'{RED}[CONNECTION FAIL]{RESET} {host}:{self.port} - {type(e).__name__}')
            return (host, False)
        except Exception as e:
            print(f'{RED}[CRITICAL]{RESET} {host}:{self.port} - {type(e).__name__}: {str(e)}')
            return (host, False)

    def load_hosts(self) -> List[str]:
        """Load hosts from the user-specified hosts file."""
        filename = self.hosts_file
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Hosts file '{filename}' not found.")
            
        hosts = []
        with open(filename, 'r') as f:
            for line in f:
                host = line.strip()
                if host and not host.startswith('#'):
                    try:
                        if ':' in host:
                            host = host.split(':')[0]
                        
                        parsed = urlparse(f"//{'[::1]' if ':' in host else host}")
                        if not parsed.hostname:
                             raise ValueError("Invalid host format")
                        hosts.append(parsed.hostname)
                    except Exception as e:
                        print(f'{YELLOW}[SKIP]{RESET} Invalid host: {host} - {e}')
        return hosts

    def run_scan(self, hosts: List[str]) -> Tuple[Dict[str, bool], int, int, float]:
        """Run a threaded scan of all hosts."""
        if not hosts:
            print(f"{YELLOW}No valid hosts found to scan.{RESET}")
            return {}, 0, 0, 0.0
            
        results = {}
        # Clear the success log file at start of the scan
        open(self.success_log_file, 'w').close()
        
        print(f"\n{CYAN}--- Starting Scan ---{RESET}")
        print(f"{CYAN}Protocol: {self.protocol.upper()} | Targets: {len(hosts)} | Host File: {self.hosts_file}{RESET}")
        print("-" * 30)
        
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_host = {executor.submit(self.check_host, host): host for host in hosts}
            
            for future in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    _, success = future.result()
                    results[host] = success
                except Exception as e:
                    print(f'{RED}[THREAD ERROR]{RESET} {host} - {type(e).__name__}')
                    results[host] = False
        
        end_time = time.time()
        duration = end_time - start_time
        successful_hosts = sum(results.values())
        
        print("\n" + "=" * 30)
        print(f"{CYAN}--- Scan Complete ---{RESET}")
        print(f"Total Hosts Scanned: {len(hosts)}")
        print(f"{GREEN}Successful Hosts: {successful_hosts}{RESET}")
        print(f"{RED}Failed Hosts: {len(hosts) - successful_hosts}{RESET}")
        print(f"Time Taken: {duration:.2f} seconds")
        print(f"Successful hosts logged to: {self.success_log_file}")
        print("=" * 30)
        
        return results, successful_hosts, len(hosts), duration

# --- Telegram Bot Functions ---

async def start(update: Update, context: CallbackContext) -> None:
    """Send a message when the command /start is issued."""
    user = update.effective_user
    user_id = user.id
    
    # Check rate limiting
    can_access, error_msg = UserManager.can_user_access(user_id)
    if not can_access:
        await update.message.reply_text(error_msg, parse_mode='Markdown')
        return
    
    # Initialize user session
    if user_id not in user_sessions:
        user_sessions[user_id] = {'scan_type': None}
    
    # Check user's request status
    can_request, status_msg, remaining = UserManager.can_make_request(user_id, context)
    
    # Create main menu keyboard
    keyboard = [
        [InlineKeyboardButton("🔍 Network Scanner", callback_data="scanner")],
        [InlineKeyboardButton("📢 Our Channels", callback_data="channels")],
        [InlineKeyboardButton("✅ Verify Membership", callback_data="verify")],
        [InlineKeyboardButton("ℹ️ About", callback_data="about"),
         InlineKeyboardButton("🆘 Help", callback_data="help")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    welcome_text = (
        f"👋 Welcome {user.first_name}!\n\n"
        f"🤖 **Network Scanner Bot**\n\n"
        f"📊 **Your Daily Status:** {status_msg}\n\n"
        "🔹 **Advanced Protocol Scanning**\n"
        "🔹 **Multi-threaded Performance**\n"
        "🔹 **Real-time Results**\n\n"
        f"**Free Users:** {MAX_REQUESTS_FREE} scans/day\n"
        f"**Channel Members:** {MAX_REQUESTS_PREMIUM} scans/day\n\n"
        "Join our channels for more daily scans!"
    )
    
    await update.message.reply_text(welcome_text, reply_markup=reply_markup, parse_mode='Markdown')

async def verify_membership(update: Update, context: CallbackContext) -> None:
    """Verify if user has joined all channels"""
    user = update.effective_user
    user_id = user.id
    
    try:
        has_joined = await UserManager.check_channel_membership(user_id, context)
        
        if has_joined:
            # Update user status
            if user_id in user_requests:
                user_requests[user_id]['joined_channels'] = True
            
            can_request, status_msg, remaining = UserManager.can_make_request(user_id, context)
            
            await update.message.reply_text(
                f"✅ **Membership Verified!**\n\n"
                f"Thanks for joining our channels! You now have **{MAX_REQUESTS_PREMIUM} scans per day**.\n\n"
                f"{status_msg}",
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text(
                f"❌ **Channel Membership Required**\n\n"
                f"Please join ALL our channels to unlock {MAX_REQUESTS_PREMIUM} daily scans.\n\n"
                f"Use /channels to see the channel links and join them.\n"
                f"Then use /verify again to check your membership.",
                parse_mode='Markdown'
            )
    except Exception as e:
        logging.error(f"Error verifying membership: {e}")
        await update.message.reply_text(
            "❌ Error verifying channel membership. Please try again later.",
            parse_mode='Markdown'
        )

async def help_command(update: Update, context: CallbackContext) -> None:
    """Send a message when the command /help is issued."""
    user_id = update.effective_user.id
    can_request, status_msg, remaining = UserManager.can_make_request(user_id, context)
    
    help_text = (
        f"🤖 **Network Scanner Bot Help**\n\n"
        f"📊 **Your Status:** {status_msg}\n\n"
        "**Available Protocols:**\n"
        "• 🛡️ **TLS Scan** - WebSocket TLS tunnels\n"
        "• 🌐 **HTTP Scan** - HTTP proxy servers\n"
        "• ⚡ **VLESS Scan** - V2Ray/VLESS protocols\n\n"
        "**Rate Limits:**\n"
        f"• Free: {MAX_REQUESTS_FREE} scans per day\n"
        f"• Channel Members: {MAX_REQUESTS_PREMIUM} scans per day\n"
        f"• Global: {MAX_USERS_PER_HOUR} users per hour\n\n"
        "**How to Use:**\n"
        "1. Click 'Network Scanner'\n"
        "2. Choose scan type\n"
        "3. Upload hosts.txt file\n"
        "4. Get results with working hosts\n\n"
        "**File Format:**\n"
        "```\n"
        "host1.com\n"
        "host2.net\n"
        "192.168.1.1\n"
        "```\n\n"
        "**Commands:**\n"
        "/start - Start the bot\n"
        "/help - Show this help\n"
        "/scan - Start scanner\n"
        "/channels - Show our channels\n"
        "/verify - Check channel membership\n"
        "/status - Check your usage"
    )
    
    keyboard = [
        [InlineKeyboardButton("🔍 Scanner", callback_data="scanner")],
        [InlineKeyboardButton("📢 Channels", callback_data="channels")],
        [InlineKeyboardButton("✅ Verify", callback_data="verify")],
        [InlineKeyboardButton("🔙 Main Menu", callback_data="main")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    if update.callback_query:
        await update.callback_query.edit_message_text(help_text, reply_markup=reply_markup, parse_mode='Markdown')
    else:
        await update.message.reply_text(help_text, reply_markup=reply_markup, parse_mode='Markdown')

async def status_command(update: Update, context: CallbackContext) -> None:
    """Check user's current status and usage"""
    user_id = update.effective_user.id
    can_request, status_msg, remaining = UserManager.can_make_request(user_id, context)
    
    # Check channel membership
    has_joined = False
    if user_id in user_requests:
        has_joined = user_requests[user_id]['joined_channels']
    
    status_text = (
        f"📊 **Your Account Status**\n\n"
        f"{status_msg}\n\n"
        f"**Channel Membership:** {'✅ Verified' if has_joined else '❌ Not Verified'}\n"
        f"**Daily Limit:** {MAX_REQUESTS_PREMIUM if has_joined else MAX_REQUESTS_FREE} scans\n"
        f"**Remaining Today:** {remaining} scans\n\n"
    )
    
    if not has_joined:
        status_text += f"💎 **Pro Tip:** Join our channels to get {MAX_REQUESTS_PREMIUM} scans per day!\nUse /channels to join."
    
    keyboard = [
        [InlineKeyboardButton("📢 Join Channels", callback_data="channels")],
        [InlineKeyboardButton("✅ Verify Membership", callback_data="verify")],
        [InlineKeyboardButton("🔍 Start Scanning", callback_data="scanner")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(status_text, reply_markup=reply_markup, parse_mode='Markdown')

async def show_scanner_menu(update: Update, context: CallbackContext) -> None:
    """Show scanner menu with protocol options."""
    user_id = update.effective_user.id
    
    # Check if user can make requests
    can_request, status_msg, remaining = UserManager.can_make_request(user_id, context)
    if not can_request:
        if update.callback_query:
            await update.callback_query.answer(status_msg, show_alert=True)
        else:
            await update.message.reply_text(status_msg, parse_mode='Markdown')
        return
    
    # Initialize user session if not exists
    if user_id not in user_sessions:
        user_sessions[user_id] = {'scan_type': None}
    
    scanner_text = (
        f"🔍 **Network Scanner**\n\n"
        f"📊 **Remaining scans today:** {remaining}\n\n"
        "**Available Scan Protocols:**\n\n"
        "• 🛡️ **TLS Scan**\n"
        "  - Port: 443\n"
        "  - Checks: WebSocket TLS tunnels\n"
        "  - SNI: nl1.wstunnel.xyz\n\n"
        "• 🌐 **HTTP Scan**\n"
        "  - Port: 443\n"
        "  - Checks: HTTP 200 OK response\n"
        "  - Standard HTTP protocol\n\n"
        "• ⚡ **VLESS Scan**\n"
        "  - Port: 443\n"
        "  - Checks: V2Ray/VLESS protocols\n"
        "  - Path: /vpnjantit\n\n"
        "**Instructions:**\n"
        "1. Choose protocol below\n"
        "2. Upload hosts.txt file\n"
        "3. Get results instantly"
    )
    
    keyboard = [
        [InlineKeyboardButton("🛡️ TLS Scan", callback_data="scan_tls"),
         InlineKeyboardButton("🌐 HTTP Scan", callback_data="scan_http")],
        [InlineKeyboardButton("⚡ VLESS Scan", callback_data="scan_vless")],
        [InlineKeyboardButton("📁 Upload Hosts File", callback_data="upload_ready")],
        [InlineKeyboardButton("📊 Check Status", callback_data="status"),
         InlineKeyboardButton("🔙 Main Menu", callback_data="main")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    if update.callback_query:
        await update.callback_query.edit_message_text(scanner_text, reply_markup=reply_markup, parse_mode='Markdown')
    else:
        await update.message.reply_text(scanner_text, reply_markup=reply_markup, parse_mode='Markdown')

async def handle_scan_selection(update: Update, context: CallbackContext) -> None:
    """Handle scan protocol selection."""
    query = update.callback_query
    user_id = update.effective_user.id
    await query.answer()
    
    # Check if user can make requests
    can_request, status_msg, remaining = UserManager.can_make_request(user_id, context)
    if not can_request:
        await query.answer(status_msg, show_alert=True)
        return
    
    if query.data.startswith('scan_'):
        scan_type = query.data.replace('scan_', '')
        
        # Store scan type in user session
        if user_id not in user_sessions:
            user_sessions[user_id] = {}
        user_sessions[user_id]['scan_type'] = scan_type
        
        protocol_info = {
            'tls': {'name': 'TLS', 'port': 443, 'sni': 'nl1.wstunnel.xyz'},
            'http': {'name': 'HTTP', 'port': 443, 'sni': 'None'},
            'vless': {'name': 'VLESS', 'port': 443, 'sni': 'sa3.vpnjantit.com'}
        }
        
        info = protocol_info[scan_type]
        
        selection_text = (
            f"🎯 **{info['name']} Scan Selected**\n\n"
            f"**Protocol:** {info['name']}\n"
            f"**Port:** {info['port']}\n"
            f"**SNI:** {info['sni']}\n\n"
            f"📊 **Remaining scans today:** {remaining}\n\n"
            "📤 **Now upload your hosts.txt file**\n\n"
            "**File should contain:**\n"
            "```\n"
            "host1.com\n"
            "host2.net\n"
            "192.168.1.1\n"
            "```\n\n"
            "The scan will start automatically!"
        )
        
        await query.edit_message_text(selection_text, parse_mode='Markdown')
    
    elif query.data == "upload_ready":
        await query.edit_message_text(
            "📤 **Ready for File Upload**\n\n"
            "Please upload your hosts.txt file now.\n\n"
            "**Requirements:**\n"
            "• File must be named 'hosts.txt'\n"
            "• One host per line\n"
            "• Supported: domain.com, ip.address\n\n"
            "After upload, I'll ask for scan type.",
            parse_mode='Markdown'
        )

async def handle_file_upload(update: Update, context: CallbackContext) -> None:
    """Handle hosts.txt file upload and start scanning."""
    try:
        user = update.effective_user
        user_id = user.id
        
        # Check if user can make requests
        can_request, status_msg, remaining = UserManager.can_make_request(user_id, context)
        if not can_request:
            await update.message.reply_text(status_msg, parse_mode='Markdown')
            return
        
        document = update.message.document
        
        if not document.file_name or not document.file_name.endswith('.txt'):
            await update.message.reply_text(
                "❌ Please upload a valid .txt file.\n\n"
                "The file should be named 'hosts.txt' and contain hosts list.",
                parse_mode='Markdown'
            )
            return
        
        # Download the file with user-specific name
        file = await context.bot.get_file(document.file_id)
        file_path = f"user_{user_id}_hosts.txt"
        await file.download_to_drive(file_path)
        
        # Check if user has scan type selected
        if user_id not in user_sessions or user_sessions[user_id].get('scan_type') is None:
            keyboard = [
                [InlineKeyboardButton("🛡️ TLS", callback_data="scan_tls"),
                 InlineKeyboardButton("🌐 HTTP", callback_data="scan_http")],
                [InlineKeyboardButton("⚡ VLESS", callback_data="scan_vless")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await update.message.reply_text(
                "📥 **File received!**\n\n"
                "Now choose scan protocol:",
                reply_markup=reply_markup,
                parse_mode='Markdown'
            )
            return
        
        # Increment request count
        UserManager.increment_request_count(user_id)
        
        # Start scan with selected protocol
        scan_type = user_sessions[user_id]['scan_type']
        await start_scan_process(update, context, file_path, scan_type, user_id)
        
    except Exception as e:
        logging.error(f"Error handling file upload: {e}")
        await update.message.reply_text(
            "❌ Error processing your file. Please try again.",
            parse_mode='Markdown'
        )

async def start_scan_process(update: Update, context: CallbackContext, file_path: str, scan_type: str, user_id: int):
    """Start the scanning process."""
    try:
        protocol_names = {
            'tls': 'TLS', 
            'http': 'HTTP',
            'vless': 'VLESS'
        }
        
        # Send initial status
        status_msg = await update.message.reply_text(
            f"🔍 **Starting {protocol_names[scan_type]} Scan**\n"
            f"📁 Loading hosts file... ⏳",
            parse_mode='Markdown'
        )
        
        # Initialize scanner with user-specific file
        scanner = NetworkScanner(scan_type, file_path)
        hosts = scanner.load_hosts()
        
        if not hosts:
            await status_msg.edit_text(
                "❌ **No valid hosts found!**\n\n"
                "Please check your hosts.txt file.\n"
                "It should contain one host per line.",
                parse_mode='Markdown'
            )
            # Clean up junks
            if os.path.exists(file_path):
                os.remove(file_path)
            return
        
        await status_msg.edit_text(
            f"🔍 **{protocol_names[scan_type]} Scan Running**\n"
            f"🎯 Targets: {len(hosts)} hosts\n"
            f"⚡ Threads: {scanner.max_workers}\n"
            f"🔄 Scanning...",
            parse_mode='Markdown'
        )
        
        # Run scan
        results, successful, total, duration = scanner.run_scan(hosts)
        
        # Get updated user status
        can_request, status_msg, remaining = UserManager.can_make_request(user_id, context)
        
        # Prepare results
        result_text = (
            f"✅ **Scan Complete!**\n\n"
            f"**Protocol:** {protocol_names[scan_type]}\n"
            f"**Total Hosts:** {total}\n"
            f"**✅ Working:** {successful}\n"
            f"**❌ Failed:** {total - successful}\n"
            f"**⏱️ Duration:** {duration:.2f}s\n\n"
            f"📊 **Remaining scans today:** {remaining}\n\n"
        )
        
        # Create back button
        back_keyboard = [
            [InlineKeyboardButton("🔙 Back to Scanner", callback_data="scanner")],
            [InlineKeyboardButton("📊 Check Status", callback_data="status")],
            [InlineKeyboardButton("🏠 Main Menu", callback_data="main")]
        ]
        back_reply_markup = InlineKeyboardMarkup(back_keyboard)
        
        if successful > 0:
            result_text += f"🎯 **Found {successful} working hosts!**\n"
            # Send the results file with back button
            with open(scanner.success_log_file, 'rb') as result_file:
                await update.message.reply_document(
                    document=result_file,
                    filename=f"{scan_type}_results_{user_id}.txt",
                    caption=result_text,
                    parse_mode='Markdown',
                    reply_markup=back_reply_markup
                )
        else:
            result_text += "😞 No working hosts found.\n"
            await update.message.reply_text(
                result_text, 
                parse_mode='Markdown',
                reply_markup=back_reply_markup
            )
        
        # Clean up user-specific files
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(scanner.success_log_file):
            os.remove(scanner.success_log_file)
            
    except Exception as e:
        logging.error(f"Error in scan process for user {user_id}: {e}")
        
        # Create back button for error message too
        error_keyboard = [
            [InlineKeyboardButton("🔙 Back to Scanner", callback_data="scanner")],
            [InlineKeyboardButton("🏠 Main Menu", callback_data="main")]
        ]
        error_reply_markup = InlineKeyboardMarkup(error_keyboard)
        
        await update.message.reply_text(
            f"❌ **Scan Failed**\n\nError: {str(e)}",
            parse_mode='Markdown',
            reply_markup=error_reply_markup
        )

async def show_channels(update: Update, context: CallbackContext) -> None:
    """Show channel links."""
    channels_text = (
        "📢 **Join Our Channels**\n\n"
        "Stay updated with our latest content and get **premium benefits**:\n\n"
        f"• **{MAX_REQUESTS_PREMIUM} scans per day** (instead of {MAX_REQUESTS_FREE})\n"
        "• Priority access during high traffic\n"
        "• Latest updates and features\n\n"
        "**Required Channels:**\n"
    )
    
    for channel in CHANNELS:
        channels_text += f"• {channel['name']}\n"
    
    channels_text += "\nClick the buttons below to join:"
    
    keyboard = []
    for channel in CHANNELS:
        keyboard.append([InlineKeyboardButton(channel["name"], url=channel["url"])])
    
    keyboard.append([InlineKeyboardButton("✅ Verify Membership", callback_data="verify")])
    keyboard.append([InlineKeyboardButton("🔍 Scanner", callback_data="scanner"),
                     InlineKeyboardButton("🔙 Main Menu", callback_data="main")])
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    if update.callback_query:
        await update.callback_query.edit_message_text(channels_text, reply_markup=reply_markup, parse_mode='Markdown')
    else:
        await update.message.reply_text(channels_text, reply_markup=reply_markup, parse_mode='Markdown')

async def button_handler(update: Update, context: CallbackContext) -> None:
    """Handle button callbacks."""
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    
    if query.data == "main":
        # Return to main menu
        keyboard = [
            [InlineKeyboardButton("🔍 Network Scanner", callback_data="scanner")],
            [InlineKeyboardButton("📢 Our Channels", callback_data="channels")],
            [InlineKeyboardButton("✅ Verify Membership", callback_data="verify")],
            [InlineKeyboardButton("ℹ️ About", callback_data="about"),
             InlineKeyboardButton("🆘 Help", callback_data="help")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        can_request, status_msg, remaining = UserManager.can_make_request(user_id, context)
        
        welcome_text = (
            f"👋 Welcome back {update.effective_user.first_name}!\n\n"
            f"🤖 **Network Scanner Bot**\n\n"
            f"📊 **Your Daily Status:** {status_msg}\n\n"
            "🔹 **Hydra Protocol Scanning**\n"
            "🔹 **Multi-threaded Performance**\n"
            "🔹 **Real-time Results**\n\n"
            f"**Free Users:** {MAX_REQUESTS_FREE} scans/day\n"
            f"**Channel Members:** {MAX_REQUESTS_PREMIUM} scans/day\n\n"
            "Join our channels for more daily scans fam!"
        )
        
        await query.edit_message_text(welcome_text, reply_markup=reply_markup, parse_mode='Markdown')
    
    elif query.data == "scanner":
        await show_scanner_menu(update, context)
    
    elif query.data == "channels":
        await show_channels(update, context)
    
    elif query.data == "verify":
        await verify_membership(update, context)
    
    elif query.data == "help":
        await help_command(update, context)
    
    elif query.data == "about":
        about_text = (
            "🤖 **Hydra Network Scanner Bot**\n\n"
            "**Version:** 1.0\n"
            "**Developer:** @lookingforme8\n\n"
            "**Features:**\n"
            "• Multi-protocol scanning (TLS/HTTP/VLESS)\n"
            "• High-performance threaded scanning per net\n"
            "• Real-time results with logging file\n"
            "• Rate limiting and user management\n"
            "• Channel membership verification\n\n"
            "**Technical Details:**\n"
            f"• Max Workers: 30 threads\n"
            f"• Connection Timeout: 10s\n"
            f"• Rate Limit Delay: 0.1s\n"
            f"• Max Users/Hour: {MAX_USERS_PER_HOUR}\n\n"
            "**Support:**\n"
            "For issues or questions, contact @lookingforme8"
        )
        
        keyboard = [
            [InlineKeyboardButton("🔍 Scanner", callback_data="scanner")],
            [InlineKeyboardButton("📢 Channels", callback_data="channels")],
            [InlineKeyboardButton("🆘 Help", callback_data="help")],
            [InlineKeyboardButton("🔙 Main Menu", callback_data="main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(about_text, reply_markup=reply_markup, parse_mode='Markdown')
    
    elif query.data == "status":
        can_request, status_msg, remaining = UserManager.can_make_request(user_id, context)
        has_joined = user_requests.get(user_id, {}).get('joined_channels', False)
        
        status_text = (
            f"📊 **Your Account Status**\n\n"
            f"{status_msg}\n\n"
            f"**Channel Membership:** {'✅ Verified' if has_joined else '❌ Not Verified'}\n"
            f"**Daily Limit:** {MAX_REQUESTS_PREMIUM if has_joined else MAX_REQUESTS_FREE} scans\n"
            f"**Remaining Today:** {remaining} scans\n\n"
        )
        
        if not has_joined:
            status_text += f"💎 **Pro Tip:** Join our channels to get {MAX_REQUESTS_PREMIUM} scans per day fam.!! "
        
        keyboard = [
            [InlineKeyboardButton("📢 Join Channels", callback_data="channels")],
            [InlineKeyboardButton("✅ Verify Membership", callback_data="verify")],
            [InlineKeyboardButton("🔍 Start Scanning", callback_data="scanner")],
            [InlineKeyboardButton("🔙 Main Menu", callback_data="main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(status_text, reply_markup=reply_markup, parse_mode='Markdown')
    
    elif query.data.startswith('scan_'):
        await handle_scan_selection(update, context)
    
    elif query.data == "upload_ready":
        await handle_scan_selection(update, context)

async def error_handler(update: Update, context: CallbackContext) -> None:
    """Handle errors in the bot."""
    logging.error(f"Exception while handling an update: {context.error}")
    
    # Notify owner about critical errors
    try:
        if OWNER_CHAT_ID:
            error_msg = f"❌ Bot Error:\n{type(context.error).__name__}: {context.error}"
            await context.bot.send_message(chat_id=OWNER_CHAT_ID, text=error_msg)
    except Exception as e:
        logging.error(f"Failed to send error notification: {e}")

def run_bot():
    """Run the Telegram bot"""
    global bot_running, application
    
    try:
        # Create the Application
        application = Application.builder().token(BOT_TOKEN).build()

        # Add handlers
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("help", help_command))
        application.add_handler(CommandHandler("scan", show_scanner_menu))
        application.add_handler(CommandHandler("channels", show_channels))
        application.add_handler(CommandHandler("verify", verify_membership))
        application.add_handler(CommandHandler("status", status_command))
        
        # Handle file uploads
        application.add_handler(MessageHandler(filters.Document.ALL, handle_file_upload))
        
        # Handle button callbacks
        application.add_handler(CallbackQueryHandler(button_handler))
        
        # Handle errors
        application.add_error_handler(error_handler)

        # Start the Bot
        print(f"{GREEN}🤖 Bot is running...{RESET}")
        print(f"{CYAN}Protocols: TLS, HTTP, VLESS{RESET}")
        print(f"{YELLOW}Max users per hour: {MAX_USERS_PER_HOUR}{RESET}")
        print(f"{BLUE}Free requests: {MAX_REQUESTS_FREE}, Premium: {MAX_REQUESTS_PREMIUM}{RESET}")
        
        bot_running = True
        
        # Run the bot with polling and proper cleanup
        application.run_polling(
            allowed_updates=Update.ALL_TYPES, 
            drop_pending_updates=True,
            close_loop=False
        )
        
    except Exception as e:
        logging.error(f"Bot error: {e}")
        bot_running = False
    finally:
        bot_running = False

def main():
    """Main function to run both Flask app and Telegram bot"""
    # Start bot in a separate thread
    print("🚀 Starting Telegram Bot...")
    bot_thread = threading.Thread(target=run_bot, daemon=True)
    bot_thread.start()
    
    # Get port from environment variable (Render sets this)
    port = int(os.environ.get('PORT', 10000))
    
    # Run Flask app
    print(f"🌐 Starting web server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

if __name__ == '__main__':
    main()