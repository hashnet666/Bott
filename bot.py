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

# Bot Configuration
BOT_TOKEN = os.environ.get('BOT_TOKEN')
OWNER_CHAT_ID = os.environ.get('OWNER_CHAT_ID')

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN environment variable is required")

# Channel links
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
    @staticmethod
    def can_user_access(user_id: int) -> Tuple[bool, str]:
        current_hour = int(time.time() // 3600)
        
        for hour in list(hourly_users.keys()):
            if hour < current_hour - 1:
                del hourly_users[hour]
        
        if current_hour not in hourly_users:
            hourly_users[current_hour] = set()
        
        if len(hourly_users[current_hour]) >= MAX_USERS_PER_HOUR:
            return False, f"❌ Bot is currently at capacity. Please try again in the next hour. (Max {MAX_USERS_PER_HOUR} users/hour)"
        
        hourly_users[current_hour].add(user_id)
        return True, ""
    
    @staticmethod
    def can_make_request(user_id: int) -> Tuple[bool, str, int]:
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
        if user_id not in user_requests:
            user_requests[user_id] = {
                'count': 1,
                'last_reset': time.time(),
                'joined_channels': False
            }
        else:
            user_requests[user_id]['count'] += 1

class NetworkScanner:
    def __init__(self, protocol: str, hosts_file: str):
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

        if self.protocol == 'tls':
            self.success_response = 'HTTP/1.1 101 Switching Protocols'
            self.ssl_context = self._create_ssl_context()
            self.server_hostname = 'nl1.wstunnel.xyz'
        
        elif self.protocol == 'http':
            self.success_response = 'HTTP/1.1 200 OK'

        elif self.protocol == 'vless':
            self.success_response = 'HTTP/1.1 101 Switching Protocols'
            self.ssl_context = self._create_ssl_context()
            self.server_hostname = 'sa3.vpnjantit.com'
            self.vless_path = '/vpnjantit'

        else:
            raise ValueError("Unsupported protocol. Choose 'http', 'tls', or 'vless'.")

    def _create_ssl_context(self):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def _generate_handshake(self, host: str) -> bytes:
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
        try:
            with open(self.success_log_file, 'a') as log_file:
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                log_file.write(f"{timestamp} - {self.protocol.upper()}://{host}:{self.port}\n")
        except IOError as e:
            print(f"LOG ERROR: Could not write to log file: {e}")

    def check_host(self, host: str) -> Tuple[str, bool]:
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

                if self.protocol in ['tls', 'vless'] and response.startswith('HTTP/1.1 101 Switching Protocols'):
                    self._log_successful_host(host)
                    return (host, True)
                
                elif self.protocol == 'http' and response.startswith(self.success_response):
                    self._log_successful_host(host)
                    return (host, True)
                    
                else:
                    return (host, False)
                        
        except socket.timeout:
            return (host, False)
        except (socket.error, ssl.SSLError, ConnectionRefusedError) as e:
            return (host, False)
        except Exception as e:
            return (host, False)

    def load_hosts(self) -> List[str]:
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
                    except Exception:
                        continue
        return hosts

    def run_scan(self, hosts: List[str]) -> Tuple[Dict[str, bool], int, int, float]:
        if not hosts:
            return {}, 0, 0, 0.0
            
        results = {}
        open(self.success_log_file, 'w').close()
        
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_host = {executor.submit(self.check_host, host): host for host in hosts}
            
            for future in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    _, success = future.result()
                    results[host] = success
                except Exception:
                    results[host] = False
        
        end_time = time.time()
        duration = end_time - start_time
        successful_hosts = sum(results.values())
        
        return results, successful_hosts, len(hosts), duration

# Telegram Bot Functions
async def start(update: Update, context: CallbackContext) -> None:
    user = update.effective_user
    user_id = user.id
    
    can_access, error_msg = UserManager.can_user_access(user_id)
    if not can_access:
        await update.message.reply_text(error_msg)
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
        f"🤖 **Network Scanner Bot**\n\n"
        f"📊 **Your Daily Status:** {status_msg}\n\n"
        "🔹 **Advanced Protocol Scanning**\n"
        "🔹 **Multi-threaded Performance**\n"
        "🔹 **Real-time Results**\n\n"
        f"**Free Users:** {MAX_REQUESTS_FREE} scans/day\n"
        f"**Channel Members:** {MAX_REQUESTS_PREMIUM} scans/day\n\n"
        "Join our channels for more daily scans!"
    )
    
    await update.message.reply_text(welcome_text, reply_markup=reply_markup)

async def help_command(update: Update, context: CallbackContext) -> None:
    user_id = update.effective_user.id
    can_request, status_msg, remaining = UserManager.can_make_request(user_id)
    
    help_text = (
        f"🤖 **Network Scanner Bot Help**\n\n"
        f"📊 **Your Status:** {status_msg}\n\n"
        "**Available Protocols:**\n"
        "• TLS Scan - WebSocket TLS tunnels\n"
        "• HTTP Scan - HTTP proxy servers\n"
        "• VLESS Scan - V2Ray/VLESS protocols\n\n"
        f"**Free:** {MAX_REQUESTS_FREE} scans per day\n"
        f"**Channel Members:** {MAX_REQUESTS_PREMIUM} scans per day\n"
        "Use /scan to start scanning!"
    )
    
    await update.message.reply_text(help_text)

async def button_handler(update: Update, context: CallbackContext) -> None:
    query = update.callback_query
    await query.answer()
    
    if query.data == "help":
        await help_command(update, context)

async def error_handler(update: Update, context: CallbackContext) -> None:
    logging.error(f"Exception while handling an update: {context.error}")

def run_bot():
    """Run the bot in its own event loop"""
    global bot_running, application
    
    # Create a new event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        application = Application.builder().token(BOT_TOKEN).build()

        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("help", help_command))
        application.add_handler(CallbackQueryHandler(button_handler))
        application.add_error_handler(error_handler)

        print("🤖 Bot is starting...")
        bot_running = True
        
        # Run the bot using the event loop
        loop.run_until_complete(application.initialize())
        loop.run_until_complete(application.start())
        print("✅ Bot is now running!")
        
        # Keep the bot running
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
    print("🚀 Starting Telegram Bot...")
    
    # Start bot in a separate thread
    bot_thread = threading.Thread(target=run_bot, daemon=True)
    bot_thread.start()
    
    # Start Flask app in main thread
    port = int(os.environ.get('PORT', 10000))
    print(f"🌐 Starting web server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

if __name__ == '__main__':
    main()
