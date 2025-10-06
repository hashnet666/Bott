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
import asyncio
import threading

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

# Global variables
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
    return jsonify({"status": "healthy"})

class UserManager:
    """Manage user access, rate limiting, and channel verification"""
    
    @staticmethod
    def can_user_access(user_id: int) -> Tuple[bool, str]:
        """Check if user can access the bot with rate limiting"""
        current_hour = int(time.time() // 3600)
        
        # Clean old hourly data
        for hour in list(hourly_users.keys()):
            if hour < current_hour - 1:
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
    def can_make_request(user_id: int) -> Tuple[bool, str, int]:
        """Check if user can make a scan request"""
        now = time.time()
        
        if user_id not in user_requests:
            user_requests[user_id] = {
                'count': 0,
                'last_reset': now,
                'joined_channels': False
            }
        
        user_data = user_requests[user_id]
        
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
        self.hosts_file = hosts_file
        self.max_workers = 30
        self.connect_timeout = 10
        self.rate_limit_delay = 0.1
        self.success_log_file = 'Host_File.txt'

        self.protocol = protocol.lower()
        self.ssl_context = None
        self.success_response = ''
        self.server_hostname = None
        self.vless_path = None
        self.port = 443

        # Server type detection
        self.server_types = {
            'cloudflare': ['cloudflare', 'cf-ray'],
            'nginx': ['nginx', 'server: nginx'],
            'apache': ['apache', 'server: apache'],
            'caddy': ['caddy', 'server: caddy'],
            'openresty': ['openresty'],
            'litespeed': ['litespeed'],
            'microsoft-iis': ['microsoft-iis', 'iis']
        }

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

    def _detect_server_type(self, response: str) -> str:
        """Detect server type from HTTP response headers."""
        response_lower = response.lower()
        
        for server_type, indicators in self.server_types.items():
            for indicator in indicators:
                if indicator in response_lower:
                    return server_type
        
        return 'unknown'

    def _log_successful_host(self, host: str, server_type: str = 'unknown'):
        """Log a successful host to the Host_File.txt log file."""
        try:
            with open(self.success_log_file, 'a') as log_file:
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                log_file.write(f"{timestamp} - {self.protocol.upper()}://{host}:{self.port} (Server: {server_type.upper()})\n")
        except IOError as e:
            print(f"{RED}[LOG ERROR]{RESET} Could not write to log file: {e}")

    def check_host(self, host: str) -> Tuple[str, bool, str]:
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

                # Detect server type
                server_type = self._detect_server_type(response)

                if self.protocol in ['tls', 'vless'] and response.startswith('HTTP/1.1 101 Switching Protocols'):
                    print(f'{GREEN}[SUCCESS]{RESET} {host}:{self.port} ({self.protocol.upper()} Tunnel Ready) - Server: {server_type.upper()}')
                    self._log_successful_host(host, server_type)
                    return (host, True, server_type)
                
                elif response.startswith(self.success_response):
                    print(f'{GREEN}[SUCCESS]{RESET} {host}:{self.port} (Expected Response: {self.success_response}) - Server: {server_type.upper()}')
                    self._log_successful_host(host, server_type)
                    return (host, True, server_type)
                    
                else:
                    error_line = response.splitlines()[0] if response else "No valid response header"
                    print(f'{YELLOW}[RESPONSE MISMATCH]{RESET} {host}:{self.port} - Expected: {self.success_response[:10]}... Got: {error_line[:60]}...')
                    return (host, False, 'unknown')
                        
        except socket.timeout:
            print(f'{RED}[TIMEOUT]{RESET} {host}:{self.port}')
            return (host, False, 'unknown')
        except (socket.error, ssl.SSLError, ConnectionRefusedError) as e:
            print(f'{RED}[CONNECTION FAIL]{RESET} {host}:{self.port} - {type(e).__name__}')
            return (host, False, 'unknown')
        except Exception as e:
            print(f'{RED}[CRITICAL]{RESET} {host}:{self.port} - {type(e).__name__}: {str(e)}')
            return (host, False, 'unknown')

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
                        parsed = urlparse(f"//{host}")
                        if parsed.hostname:
                            hosts.append(parsed.hostname)
                    except Exception as e:
                        print(f'{YELLOW}[SKIP]{RESET} Invalid host: {host} - {e}')
        return hosts

    def run_scan(self, hosts: List[str]) -> Tuple[Dict[str, bool], int, int, float, Dict[str, int]]:
        """Run a threaded scan of all hosts."""
        if not hosts:
            print(f"{YELLOW}No valid hosts found to scan.{RESET}")
            return {}, 0, 0, 0.0, {}
            
        results = {}
        server_stats = {}
        
        # Clear the success log file at start of the scan
        open(self.success_log_file, 'w').close()
        
        print(f"\n{CYAN}--- Starting Scan ---{RESET}")
        print(f"{CYAN}Protocol: {self.protocol.upper()} | Targets: {len(hosts)} | Host File: {self.hosts_file}{RESET}")
        print("-" * 50)
        
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_host = {executor.submit(self.check_host, host): host for host in hosts}
            
            for future in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    host, success, server_type = future.result()
                    results[host] = success
                    
                    # Count server types for successful hosts
                    if success and server_type != 'unknown':
                        server_stats[server_type] = server_stats.get(server_type, 0) + 1
                        
                except Exception as e:
                    print(f'{RED}[THREAD ERROR]{RESET} {host} - {type(e).__name__}')
                    results[host] = False
        
        end_time = time.time()
        duration = end_time - start_time
        successful_hosts = sum(results.values())
        
        print("\n" + "=" * 50)
        print(f"{CYAN}--- Scan Complete ---{RESET}")
        print(f"Total Hosts Scanned: {len(hosts)}")
        print(f"{GREEN}Successful Hosts: {successful_hosts}{RESET}")
        print(f"{RED}Failed Hosts: {len(hosts) - successful_hosts}{RESET}")
        print(f"Time Taken: {duration:.2f} seconds")
        
        # Display server statistics
        if server_stats:
            print(f"\n{BLUE}--- Server Statistics ---{RESET}")
            for server_type, count in sorted(server_stats.items(), key=lambda x: x[1], reverse=True):
                print(f"{GREEN}{count} {server_type.upper()}{RESET}")
        
        print(f"\nSuccessful hosts logged to: {self.success_log_file}")
        print("=" * 50)
        
        return results, successful_hosts, len(hosts), duration, server_stats

# Telegram Bot Functions
async def start(update: Update, context: CallbackContext) -> None:
    """Send a message when the command /start is issued."""
    user = update.effective_user
    user_id = user.id
    
    can_access, error_msg = UserManager.can_user_access(user_id)
    if not can_access:
        await update.message.reply_text(error_msg, parse_mode='Markdown')
        return
    
    if user_id not in user_sessions:
        user_sessions[user_id] = {'scan_type': None}
    
    can_request, status_msg, remaining = UserManager.can_make_request(user_id)
    
    keyboard = [
        [InlineKeyboardButton("🔍 Network Scanner", callback_data="scanner")],
        [InlineKeyboardButton("📢 Our Channels", callback_data="channels")],
        [InlineKeyboardButton("✅ Verify Membership", callback_data="verify")],
        [InlineKeyboardButton("🆘 Help", callback_data="help")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    welcome_text = (
        f"👋 Welcome {user.first_name}!\n\n"
        f"🤖 **Advanced Network Scanner Bot**\n\n"
        f"📊 **Your Daily Status:** {status_msg}\n\n"
        "🔹 **Multi-Protocol Scanning** (HTTP/TLS/VLESS)\n"
        "🔹 **Server Type Detection** (Cloudflare, Nginx, Apache, etc.)\n"
        "🔹 **Real-time Results with Statistics**\n\n"
        f"**Free Users:** {MAX_REQUESTS_FREE} scans/day\n"
        f"**Channel Members:** {MAX_REQUESTS_PREMIUM} scans/day\n\n"
        "Join our channels for enhanced features!"
    )
    
    await update.message.reply_text(welcome_text, reply_markup=reply_markup, parse_mode='Markdown')

async def help_command(update: Update, context: CallbackContext) -> None:
    """Send a message when the command /help is issued."""
    user_id = update.effective_user.id
    can_request, status_msg, remaining = UserManager.can_make_request(user_id)
    
    help_text = (
        f"🤖 **Advanced Network Scanner Bot**\n\n"
        f"📊 **Your Status:** {status_msg}\n\n"
        "**Features:**\n"
        "• TLS Scan - WebSocket TLS tunnels\n"
        "• HTTP Scan - HTTP proxy servers\n"
        "• VLESS Scan - V2Ray/VLESS protocols\n"
        "• Server Type Detection (Cloudflare, Nginx, Apache, etc.)\n"
        "• Detailed Statistics Report\n\n"
        f"**Free:** {MAX_REQUESTS_FREE} scans per day\n"
        f"**Channel Members:** {MAX_REQUESTS_PREMIUM} scans per day\n\n"
        "Use /scan to start scanning with server detection!"
    )
    
    await update.message.reply_text(help_text, parse_mode='Markdown')

async def handle_file_upload(update: Update, context: CallbackContext) -> None:
    """Handle hosts.txt file upload and start scanning."""
    try:
        user = update.effective_user
        user_id = user.id
        
        can_request, status_msg, remaining = UserManager.can_make_request(user_id)
        if not can_request:
            await update.message.reply_text(status_msg, parse_mode='Markdown')
            return
        
        document = update.message.document
        
        if not document.file_name or not document.file_name.endswith('.txt'):
            await update.message.reply_text(
                "❌ Please upload a valid .txt file named 'hosts.txt'",
                parse_mode='Markdown'
            )
            return
        
        # Download the file
        file = await context.bot.get_file(document.file_id)
        file_path = f"user_{user_id}_hosts.txt"
        await file.download_to_drive(file_path)
        
        # Check scan type
        if user_id not in user_sessions or user_sessions[user_id].get('scan_type') is None:
            keyboard = [
                [InlineKeyboardButton("🛡️ TLS Scan", callback_data="scan_tls"),
                 InlineKeyboardButton("🌐 HTTP Scan", callback_data="scan_http")],
                [InlineKeyboardButton("⚡ VLESS Scan", callback_data="scan_vless")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await update.message.reply_text(
                "📥 **File received!**\n\nChoose scan protocol:",
                reply_markup=reply_markup,
                parse_mode='Markdown'
            )
            return
        
        # Increment request count and start scan
        UserManager.increment_request_count(user_id)
        scan_type = user_sessions[user_id]['scan_type']
        await start_scan_process(update, context, file_path, scan_type, user_id)
        
    except Exception as e:
        logging.error(f"Error handling file upload: {e}")
        await update.message.reply_text("❌ Error processing your file. Please try again.")

async def start_scan_process(update: Update, context: CallbackContext, file_path: str, scan_type: str, user_id: int):
    """Start the scanning process."""
    try:
        protocol_names = {'tls': 'TLS', 'http': 'HTTP', 'vless': 'VLESS'}
        
        status_msg = await update.message.reply_text(
            f"🔍 **Starting {protocol_names[scan_type]} Scan**\nLoading hosts file... ⏳",
            parse_mode='Markdown'
        )
        
        scanner = NetworkScanner(scan_type, file_path)
        hosts = scanner.load_hosts()
        
        if not hosts:
            await status_msg.edit_text("❌ **No valid hosts found!**")
            if os.path.exists(file_path):
                os.remove(file_path)
            return
        
        await status_msg.edit_text(
            f"🔍 **{protocol_names[scan_type]} Scan Running**\n"
            f"🎯 Targets: {len(hosts)} hosts\n"
            f"⚡ Threads: {scanner.max_workers}\n"
            f"🔄 Scanning with server detection...",
            parse_mode='Markdown'
        )
        
        # Run scan
        results, successful, total, duration, server_stats = scanner.run_scan(hosts)
        
        can_request, status_msg, remaining = UserManager.can_make_request(user_id)
        
        # Prepare results with server statistics
        result_text = (
            f"✅ **Scan Complete!**\n\n"
            f"**Protocol:** {protocol_names[scan_type]}\n"
            f"**Total Hosts:** {total}\n"
            f"**✅ Working:** {successful}\n"
            f"**❌ Failed:** {total - successful}\n"
            f"**⏱️ Duration:** {duration:.2f}s\n\n"
        )
        
        # Add server statistics
        if server_stats:
            result_text += "**🏗️ Server Types Found:**\n"
            for server_type, count in sorted(server_stats.items(), key=lambda x: x[1], reverse=True):
                result_text += f"• {count} {server_type.upper()}\n"
            result_text += "\n"
        
        result_text += f"📊 **Remaining scans today:** {remaining}\n\n"
        
        if successful > 0:
            result_text += f"🎯 **Found {successful} working hosts!**\n"
            with open(scanner.success_log_file, 'rb') as result_file:
                await update.message.reply_document(
                    document=result_file,
                    filename=f"{scan_type}_results_{user_id}.txt",
                    caption=result_text,
                    parse_mode='Markdown'
                )
        else:
            await update.message.reply_text(result_text, parse_mode='Markdown')
        
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(scanner.success_log_file):
            os.remove(scanner.success_log_file)
            
    except Exception as e:
        logging.error(f"Error in scan process: {e}")
        await update.message.reply_text(f"❌ **Scan Failed**\n\nError: {str(e)}")

async def button_handler(update: Update, context: CallbackContext) -> None:
    """Handle button callbacks."""
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    
    if query.data == "help":
        await help_command(update, context)
    elif query.data.startswith('scan_'):
        scan_type = query.data.replace('scan_', '')
        if user_id not in user_sessions:
            user_sessions[user_id] = {}
        user_sessions[user_id]['scan_type'] = scan_type
        await query.edit_message_text(
            f"🎯 **{scan_type.upper()} Scan Selected**\n\n"
            "📤 **Now upload your hosts.txt file**\n\n"
            "The scan will start automatically with server detection!",
            parse_mode='Markdown'
        )

async def error_handler(update: Update, context: CallbackContext) -> None:
    """Handle errors in the bot."""
    logging.error(f"Exception while handling an update: {context.error}")

def run_bot():
    """Run the bot in its own event loop"""
    global bot_running, application
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        application = Application.builder().token(BOT_TOKEN).build()

        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("help", help_command))
        application.add_handler(MessageHandler(filters.Document.ALL, handle_file_upload))
        application.add_handler(CallbackQueryHandler(button_handler))
        application.add_error_handler(error_handler)

        print("🤖 Bot is starting...")
        bot_running = True
        
        loop.run_until_complete(application.initialize())
        loop.run_until_complete(application.start())
        print("✅ Bot is now running!")
        
        loop.run_until_complete(application.updater.start_polling())
        loop.run_forever()
        
    except Exception as e:
        logging.error(f"Bot error: {e}")
        bot_running = False
    finally:
        bot_running = False
        if application:
            loop.run_until_complete(application.stop())
        loop.close()

def main():
    print("🚀 Starting Advanced Network Scanner Bot...")
    
    bot_thread = threading.Thread(target=run_bot, daemon=True)
    bot_thread.start()
    
    port = int(os.environ.get('PORT', 10000))
    print(f"🌐 Starting web server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

if __name__ == '__main__':
    main()
