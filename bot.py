#!/usr/bin/env python3
import logging
import socket
import ssl
import concurrent.futures
import os
import time
import datetime
import sqlite3
import asyncio
from urllib.parse import urlparse
from typing import List, Tuple, Dict, Optional
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler, filters, 
    CallbackContext, CallbackQueryHandler
)
from flask import Flask, jsonify

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

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

# Rate Limiting
MAX_USERS_PER_HOUR = 100
MAX_REQUESTS_FREE = 3
MAX_REQUESTS_PREMIUM = 5
REQUEST_RESET_HOURS = 24

# Flask app
app = Flask(__name__)

class DatabaseManager:
    def __init__(self, db_path: str = "bot_data.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            cursor = conn.cursor()
            
            # User requests table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_requests (
                    user_id INTEGER PRIMARY KEY,
                    request_count INTEGER DEFAULT 0,
                    last_reset REAL,
                    joined_channels BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # User sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_sessions (
                    user_id INTEGER PRIMARY KEY,
                    scan_type TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Hourly users table for rate limiting
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hourly_users (
                    hour INTEGER,
                    user_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (hour, user_id)
                )
            ''')
            
            # Scan history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    protocol TEXT,
                    total_hosts INTEGER,
                    successful_hosts INTEGER,
                    duration REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Database initialized successfully")
            
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {e}")
            raise
    
    def get_connection(self):
        """Get database connection with error handling"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as e:
            logger.error(f"Database connection error: {e}")
            raise
    
    def execute_with_retry(self, query: str, params: tuple = (), max_retries: int = 3):
        """Execute query with retry logic"""
        for attempt in range(max_retries):
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                cursor.execute(query, params)
                conn.commit()
                result = cursor.lastrowid
                conn.close()
                return result
            except sqlite3.OperationalError as e:
                if "locked" in str(e) and attempt < max_retries - 1:
                    logger.warning(f"Database locked, retrying... (attempt {attempt + 1})")
                    time.sleep(0.1 * (attempt + 1))
                else:
                    logger.error(f"Database error after {attempt + 1} attempts: {e}")
                    raise
            except sqlite3.Error as e:
                logger.error(f"Database error: {e}")
                raise
    
    def fetch_one(self, query: str, params: tuple = ()):
        """Fetch single row with error handling"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params)
            result = cursor.fetchone()
            conn.close()
            return dict(result) if result else None
        except sqlite3.Error as e:
            logger.error(f"Database fetch error: {e}")
            return None
    
    def fetch_all(self, query: str, params: tuple = ()):
        """Fetch all rows with error handling"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params)
            results = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return results
        except sqlite3.Error as e:
            logger.error(f"Database fetch all error: {e}")
            return []

# Initialize database
db = DatabaseManager()

@app.route('/')
def health_check():
    """Health check endpoint with database status"""
    try:
        # Test database connection
        db_status = "healthy"
        test_result = db.fetch_one("SELECT 1 as test")
        if not test_result:
            db_status = "unhealthy"
        
        return jsonify({
            "status": "healthy", 
            "service": "Telegram Bot",
            "database": db_status,
            "timestamp": datetime.datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            "status": "degraded",
            "service": "Telegram Bot", 
            "database": "unhealthy",
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }), 500

@app.route('/health')
def health():
    """Simple health endpoint"""
    return jsonify({"status": "healthy"})

@app.route('/stats')
def stats():
    """Bot statistics endpoint"""
    try:
        total_users = db.fetch_one("SELECT COUNT(*) as count FROM user_requests")['count']
        total_scans = db.fetch_one("SELECT COUNT(*) as count FROM scan_history")['count']
        today_scans = db.fetch_one(
            "SELECT COUNT(*) as count FROM scan_history WHERE date(created_at) = date('now')"
        )['count']
        
        return jsonify({
            "total_users": total_users,
            "total_scans": total_scans,
            "scans_today": today_scans,
            "timestamp": datetime.datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

class UserManager:
    @staticmethod
    def can_user_access(user_id: int) -> Tuple[bool, str]:
        """Check if user can access the bot (rate limiting)"""
        try:
            current_hour = int(time.time() // 3600)
            
            # Clean up old hourly data
            db.execute_with_retry(
                "DELETE FROM hourly_users WHERE hour < ?", 
                (current_hour - 1,)
            )
            
            # Count current hour users
            result = db.fetch_one(
                "SELECT COUNT(*) as count FROM hourly_users WHERE hour = ?", 
                (current_hour,)
            )
            
            current_count = result['count'] if result else 0
            
            if current_count >= MAX_USERS_PER_HOUR:
                return False, f"❌ Bot is currently at capacity. Please try again in the next hour. (Max {MAX_USERS_PER_HOUR} users/hour)"
            
            # Add user to current hour
            db.execute_with_retry(
                "INSERT OR IGNORE INTO hourly_users (hour, user_id) VALUES (?, ?)",
                (current_hour, user_id)
            )
            
            return True, ""
            
        except Exception as e:
            logger.error(f"Error in can_user_access: {e}")
            # Allow access on database error to avoid blocking users
            return True, ""
    
    @staticmethod
    def can_make_request(user_id: int) -> Tuple[bool, str, int]:
        """Check if user can make a request"""
        try:
            now = time.time()
            
            # Get or create user data
            user_data = db.fetch_one(
                "SELECT * FROM user_requests WHERE user_id = ?", 
                (user_id,)
            )
            
            if not user_data:
                # Create new user
                db.execute_with_retry(
                    "INSERT INTO user_requests (user_id, request_count, last_reset, joined_channels) VALUES (?, ?, ?, ?)",
                    (user_id, 0, now, False)
                )
                user_data = {'request_count': 0, 'last_reset': now, 'joined_channels': False}
            else:
                # Reset count if period has passed
                if now - user_data['last_reset'] >= REQUEST_RESET_HOURS * 3600:
                    db.execute_with_retry(
                        "UPDATE user_requests SET request_count = 0, last_reset = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                        (now, user_id)
                    )
                    user_data['request_count'] = 0
                    user_data['last_reset'] = now
            
            max_requests = MAX_REQUESTS_PREMIUM if user_data['joined_channels'] else MAX_REQUESTS_FREE
            remaining = max_requests - user_data['request_count']
            
            if user_data['request_count'] >= max_requests:
                reset_time = user_data['last_reset'] + (REQUEST_RESET_HOURS * 3600)
                time_left = reset_time - now
                hours_left = int(time_left // 3600)
                minutes_left = int((time_left % 3600) // 60)
                
                if user_data['joined_channels']:
                    return False, f"❌ You've used all {MAX_REQUESTS_PREMIUM} daily requests. Reset in {hours_left}h {minutes_left}m", remaining
                else:
                    message = f"❌ You've used all {MAX_REQUESTS_FREE} free daily requests.\n\n**Join our channels to get {MAX_REQUESTS_PREMIUM} requests per day!**"
                    return False, message, remaining
            
            status_msg = f"✅ Requests today: {user_data['request_count']}/{max_requests}"
            return True, status_msg, remaining
            
        except Exception as e:
            logger.error(f"Error in can_make_request: {e}")
            # Allow request on database error
            return True, "✅ Database temporarily unavailable - request allowed", 1
    
    @staticmethod
    def increment_request_count(user_id: int):
        """Increment user's request count"""
        try:
            db.execute_with_retry(
                "UPDATE user_requests SET request_count = request_count + 1, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                (user_id,)
            )
        except Exception as e:
            logger.error(f"Error incrementing request count: {e}")
    
    @staticmethod
    def set_joined_channels(user_id: int):
        """Mark user as having joined channels"""
        try:
            db.execute_with_retry(
                "UPDATE user_requests SET joined_channels = TRUE, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                (user_id,)
            )
        except Exception as e:
            logger.error(f"Error setting joined channels: {e}")
    
    @staticmethod
    def get_user_session(user_id: int) -> Optional[Dict]:
        """Get user session data"""
        try:
            return db.fetch_one(
                "SELECT * FROM user_sessions WHERE user_id = ?", 
                (user_id,)
            )
        except Exception as e:
            logger.error(f"Error getting user session: {e}")
            return None
    
    @staticmethod
    def set_user_session(user_id: int, scan_type: str = None):
        """Set user session data"""
        try:
            db.execute_with_retry(
                '''INSERT OR REPLACE INTO user_sessions 
                   (user_id, scan_type, updated_at) 
                   VALUES (?, ?, CURRENT_TIMESTAMP)''',
                (user_id, scan_type)
            )
        except Exception as e:
            logger.error(f"Error setting user session: {e}")
    
    @staticmethod
    def log_scan(user_id: int, protocol: str, total_hosts: int, successful_hosts: int, duration: float):
        """Log scan to history"""
        try:
            db.execute_with_retry(
                '''INSERT INTO scan_history 
                   (user_id, protocol, total_hosts, successful_hosts, duration)
                   VALUES (?, ?, ?, ?, ?)''',
                (user_id, protocol, total_hosts, successful_hosts, duration)
            )
        except Exception as e:
            logger.error(f"Error logging scan: {e}")

class NetworkScanner:
    def __init__(self, protocol: str, hosts_file: str):
        self.hosts_file = hosts_file
        self.max_workers = 20
        self.connect_timeout = 5
        self.rate_limit_delay = 0.05
        self.success_log_file = f'Host_File_{int(time.time())}.txt'

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
            self.success_response = 'HTTP/1.1 101'
            self.ssl_context = self._create_ssl_context()
            self.server_hostname = 'nl1.wstunnel.xyz'
        
        elif self.protocol == 'http':
            self.success_response = 'HTTP/1.1 200'

        elif self.protocol == 'vless':
            self.success_response = 'HTTP/1.1 101'
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

    def _detect_server_type(self, response: str) -> str:
        """Detect server type from HTTP response headers."""
        response_lower = response.lower()
        
        for server_type, indicators in self.server_types.items():
            for indicator in indicators:
                if indicator in response_lower:
                    return server_type
        
        return 'unknown'

    def _log_successful_host(self, host: str, server_type: str = 'unknown'):
        try:
            with open(self.success_log_file, 'a', encoding='utf-8') as log_file:
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                log_file.write(f"{timestamp} - {self.protocol.upper()}://{host}:{self.port} (Server: {server_type.upper()})\n")
        except IOError as e:
            logger.error(f"Error writing to log file: {e}")

    def check_host(self, host: str) -> Tuple[str, bool, str]:
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

                server_type = self._detect_server_type(response)

                if self.protocol in ['tls', 'vless'] and 'HTTP/1.1 101' in response:
                    self._log_successful_host(host, server_type)
                    return (host, True, server_type)
                
                elif 'HTTP/1.1 200' in response:
                    self._log_successful_host(host, server_type)
                    return (host, True, server_type)
                    
                else:
                    return (host, False, 'unknown')
                        
        except Exception as e:
            logger.debug(f"Host check failed for {host}: {e}")
            return (host, False, 'unknown')

    def load_hosts(self) -> List[str]:
        if not os.path.exists(self.hosts_file):
            raise FileNotFoundError(f"Hosts file '{self.hosts_file}' not found.")
            
        hosts = []
        with open(self.hosts_file, 'r', encoding='utf-8') as f:
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
                        logger.debug(f"Invalid host format: {host} - {e}")
                        continue
        return hosts

    def run_scan(self, hosts: List[str]) -> Tuple[Dict[str, bool], int, int, float, Dict[str, int]]:
        if not hosts:
            return {}, 0, 0, 0.0, {}
            
        results = {}
        server_stats = {}
        
        # Clear the success log file at start of scan
        open(self.success_log_file, 'w').close()
        
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_host = {executor.submit(self.check_host, host): host for host in hosts}
            
            for future in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    host, success, server_type = future.result()
                    results[host] = success
                    
                    if success and server_type != 'unknown':
                        server_stats[server_type] = server_stats.get(server_type, 0) + 1
                        
                except Exception as e:
                    logger.error(f"Error processing host {host}: {e}")
                    results[host] = False
        
        end_time = time.time()
        duration = end_time - start_time
        successful_hosts = sum(results.values())
        
        return results, successful_hosts, len(hosts), duration, server_stats

# Telegram Bot Functions
async def start(update: Update, context: CallbackContext) -> None:
    user = update.effective_user
    user_id = user.id
    
    can_access, error_msg = UserManager.can_user_access(user_id)
    if not can_access:
        await update.message.reply_text(error_msg)
        return
    
    UserManager.set_user_session(user_id)
    
    can_request, status_msg, remaining = UserManager.can_make_request(user_id)
    
    keyboard = [
        [InlineKeyboardButton("🔍 Network Scanner", callback_data="scanner")],
        [InlineKeyboardButton("📢 Our Channels", callback_data="channels")],
        [InlineKeyboardButton("🆘 Help", callback_data="help")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    welcome_text = (
        f"👋 Welcome {user.first_name}!\n\n"
        f"🤖 **Advanced Network Scanner Bot**\n\n"
        f"📊 **Your Status:** {status_msg}\n\n"
        "🔹 **Multi-Protocol Scanning**\n"
        "🔹 **Server Type Detection**\n"
        "🔹 **Real-time Results**\n\n"
        f"**Free:** {MAX_REQUESTS_FREE} scans/day\n"
        f"**Premium:** {MAX_REQUESTS_PREMIUM} scans/day\n\n"
        "Upload hosts.txt file to start scanning!"
    )
    
    await update.message.reply_text(welcome_text, reply_markup=reply_markup)

async def help_command(update: Update, context: CallbackContext) -> None:
    user_id = update.effective_user.id
    can_request, status_msg, remaining = UserManager.can_make_request(user_id)
    
    help_text = (
        f"🤖 **Network Scanner Bot**\n\n"
        f"📊 **Your Status:** {status_msg}\n\n"
        "**Features:**\n"
        "• TLS/HTTP/VLESS Protocol Scanning\n"
        "• Server Type Detection\n"
        "• Multi-threaded Performance\n\n"
        "**Usage:**\n"
        "1. Upload hosts.txt file\n"
        "2. Choose protocol\n"
        "3. Get results with server stats\n\n"
        f"**Limits:** {MAX_REQUESTS_FREE} free, {MAX_REQUESTS_PREMIUM} premium scans/day"
    )
    
    keyboard = [[InlineKeyboardButton("🔙 Back to Main", callback_data="main_menu")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    if update.callback_query:
        await update.callback_query.edit_message_text(help_text, reply_markup=reply_markup)
    else:
        await update.message.reply_text(help_text, reply_markup=reply_markup)

async def show_channels(update: Update, context: CallbackContext) -> None:
    channels_text = "📢 **Join Our Channels**\n\n"
    for channel in CHANNELS:
        channels_text += f"{channel['name']}\n{channel['url']}\n\n"
    
    channels_text += "Join all channels to get premium benefits!"
    
    keyboard = [
        [InlineKeyboardButton("✅ I've Joined All", callback_data="joined_channels")],
        [InlineKeyboardButton("🔙 Back to Main", callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    if update.callback_query:
        await update.callback_query.edit_message_text(channels_text, reply_markup=reply_markup)
    else:
        await update.message.reply_text(channels_text, reply_markup=reply_markup)

async def show_scanner_menu(update: Update, context: CallbackContext) -> None:
    user_id = update.effective_user.id
    
    can_request, status_msg, remaining = UserManager.can_make_request(user_id)
    
    menu_text = (
        f"🔍 **Network Scanner**\n\n"
        f"📊 **Your Status:** {status_msg}\n\n"
        "**Available Protocols:**\n"
        "• 🛡️ TLS Scan (WebSocket over TLS)\n"
        "• 🌐 HTTP Scan (Standard HTTP)\n"
        "• ⚡ VLESS Scan (VLESS over TLS)\n\n"
        "**Instructions:**\n"
        "1. Choose a protocol below\n"
        "2. Upload your hosts.txt file\n"
        "3. Wait for scan results\n\n"
        f"Remaining scans today: **{remaining}**"
    )
    
    keyboard = [
        [InlineKeyboardButton("🛡️ TLS Scan", callback_data="scan_tls"),
         InlineKeyboardButton("🌐 HTTP Scan", callback_data="scan_http")],
        [InlineKeyboardButton("⚡ VLESS Scan", callback_data="scan_vless")],
        [InlineKeyboardButton("🔙 Back to Main", callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    if update.callback_query:
        await update.callback_query.edit_message_text(menu_text, reply_markup=reply_markup)
    else:
        await update.message.reply_text(menu_text, reply_markup=reply_markup)

async def handle_file_upload(update: Update, context: CallbackContext) -> None:
    try:
        user = update.effective_user
        user_id = user.id
        
        can_request, status_msg, remaining = UserManager.can_make_request(user_id)
        if not can_request:
            await update.message.reply_text(status_msg)
            return
        
        document = update.message.document
        
        if not document.file_name or not document.file_name.endswith('.txt'):
            await update.message.reply_text("❌ Please upload a valid .txt file")
            return
        
        file = await context.bot.get_file(document.file_id)
        file_path = f"user_{user_id}_{int(time.time())}.txt"
        await file.download_to_drive(file_path)
        
        user_session = UserManager.get_user_session(user_id)
        if not user_session or user_session.get('scan_type') is None:
            keyboard = [
                [InlineKeyboardButton("🛡️ TLS Scan", callback_data="scan_tls"),
                 InlineKeyboardButton("🌐 HTTP Scan", callback_data="scan_http")],
                [InlineKeyboardButton("⚡ VLESS Scan", callback_data="scan_vless")],
                [InlineKeyboardButton("🔙 Back to Main", callback_data="main_menu")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await update.message.reply_text("📥 **File received!**\nChoose scan protocol:", reply_markup=reply_markup)
            return
        
        UserManager.increment_request_count(user_id)
        scan_type = user_session['scan_type']
        await start_scan_process(update, context, file_path, scan_type, user_id)
        
    except Exception as e:
        logger.error(f"Error handling file upload: {e}")
        await update.message.reply_text("❌ Error processing your file.")

async def start_scan_process(update: Update, context: CallbackContext, file_path: str, scan_type: str, user_id: int):
    try:
        protocol_names = {'tls': 'TLS', 'http': 'HTTP', 'vless': 'VLESS'}
        
        status_msg = await update.message.reply_text(f"🔍 **Starting {protocol_names[scan_type]} Scan**\nLoading hosts... ⏳")
        
        scanner = NetworkScanner(scan_type, file_path)
        hosts = scanner.load_hosts()
        
        if not hosts:
            await status_msg.edit_text("❌ **No valid hosts found!**")
            if os.path.exists(file_path):
                os.remove(file_path)
            return
        
        await status_msg.edit_text(f"🔍 **Scanning {len(hosts)} hosts**\nProtocol: {protocol_names[scan_type]}\n🔄 Running...")
        
        # Run scan in thread to avoid blocking
        loop = asyncio.get_event_loop()
        results, successful, total, duration, server_stats = await loop.run_in_executor(
            None, scanner.run_scan, hosts
        )
        
        # Log scan to database
        UserManager.log_scan(user_id, scan_type, total, successful, duration)
        
        can_request, status_msg, remaining = UserManager.can_make_request(user_id)
        
        result_text = (
            f"✅ **Scan Complete!**\n\n"
            f"**Protocol:** {protocol_names[scan_type]}\n"
            f"**Total:** {total} hosts\n"
            f"**✅ Working:** {successful}\n"
            f"**❌ Failed:** {total - successful}\n"
            f"**⏱️ Time:** {duration:.2f}s\n\n"
        )
        
        if server_stats:
            result_text += "**🏗️ Server Types:**\n"
            for server_type, count in sorted(server_stats.items(), key=lambda x: x[1], reverse=True):
                result_text += f"• {count} {server_type.upper()}\n"
            result_text += "\n"
        
        result_text += f"📊 **Remaining scans:** {remaining}\n\n"
        
        keyboard = [
            [InlineKeyboardButton("🔄 Scan Again", callback_data="scanner")],
            [InlineKeyboardButton("🔙 Back to Main", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if successful > 0:
            result_text += f"🎯 **Found {successful} working hosts!**\n"
            try:
                with open(scanner.success_log_file, 'rb') as result_file:
                    await update.message.reply_document(
                        document=result_file,
                        filename=f"results_{user_id}.txt",
                        caption=result_text,
                        reply_markup=reply_markup
                    )
            except Exception as e:
                logger.error(f"Error sending document: {e}")
                result_text += "\n❌ Could not send results file."
                await update.message.reply_text(result_text, reply_markup=reply_markup)
        else:
            await update.message.reply_text(result_text, reply_markup=reply_markup)
        
        # Cleanup files
        for file_to_remove in [file_path, scanner.success_log_file]:
            try:
                if os.path.exists(file_to_remove):
                    os.remove(file_to_remove)
            except Exception as e:
                logger.error(f"Error removing file {file_to_remove}: {e}")
            
    except Exception as e:
        logger.error(f"Scan error: {e}")
        keyboard = [[InlineKeyboardButton("🔙 Back to Main", callback_data="main_menu")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text(f"❌ **Scan Failed**\nError: {str(e)}", reply_markup=reply_markup)

async def button_handler(update: Update, context: CallbackContext) -> None:
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    
    if query.data == "main_menu":
        await start_from_query(update, context)
    elif query.data == "help":
        await help_command(update, context)
    elif query.data == "channels":
        await show_channels(update, context)
    elif query.data == "scanner":
        await show_scanner_menu(update, context)
    elif query.data == "joined_channels":
        UserManager.set_joined_channels(user_id)
        
        await query.edit_message_text(
            "✅ **Premium Activated!**\n\n"
            f"You now have {MAX_REQUESTS_PREMIUM} scans per day!\n\n"
            "Thank you for joining our channels!",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back to Main", callback_data="main_menu")]])
        )
    elif query.data.startswith('scan_'):
        scan_type = query.data.replace('scan_', '')
        UserManager.set_user_session(user_id, scan_type)
        
        protocol_names = {'tls': 'TLS', 'http': 'HTTP', 'vless': 'VLESS'}
        
        await query.edit_message_text(
            f"🎯 **{protocol_names[scan_type]} Scan Selected**\n\n"
            "Please upload your hosts.txt file to start scanning!\n\n"
            "**File format:**\n"
            "• One host per line\n"
            "• IP addresses or domains\n"
            "• Example: 192.168.1.1 or example.com",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back to Scanner", callback_data="scanner")]])
        )

async def start_from_query(update: Update, context: CallbackContext) -> None:
    query = update.callback_query
    user = query.from_user
    user_id = user.id
    
    can_access, error_msg = UserManager.can_user_access(user_id)
    if not can_access:
        await query.edit_message_text(error_msg)
        return
    
    UserManager.set_user_session(user_id)
    
    can_request, status_msg, remaining = UserManager.can_make_request(user_id)
    
    keyboard = [
        [InlineKeyboardButton("🔍 Network Scanner", callback_data="scanner")],
        [InlineKeyboardButton("📢 Our Channels", callback_data="channels")],
        [InlineKeyboardButton("🆘 Help", callback_data="help")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    welcome_text = (
        f"👋 Welcome {user.first_name}!\n\n"
        f"🤖 **Advanced Network Scanner Bot**\n\n"
        f"📊 **Your Status:** {status_msg}\n\n"
        "🔹 **Multi-Protocol Scanning**\n"
        "🔹 **Server Type Detection**\n"
        "🔹 **Real-time Results**\n\n"
        f"**Free:** {MAX_REQUESTS_FREE} scans/day\n"
        f"**Premium:** {MAX_REQUESTS_PREMIUM} scans/day\n\n"
        "Upload hosts.txt file to start scanning!"
    )
    
    await query.edit_message_text(welcome_text, reply_markup=reply_markup)

async def error_handler(update: Update, context: CallbackContext) -> None:
    logger.error(f"Bot error: {context.error}")

def run_bot():
    """Run the Telegram bot"""
    try:
        # Use a simpler application builder approach
        application = Application.builder().token(BOT_TOKEN).build()
        
        # Add handlers
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("help", help_command))
        application.add_handler(MessageHandler(filters.Document.ALL, handle_file_upload))
        application.add_handler(CallbackQueryHandler(button_handler))
        application.add_error_handler(error_handler)
        
        logger.info("🤖 Bot starting...")
        application.run_polling(drop_pending_updates=True)
    except Exception as e:
        logger.error(f"Bot failed to start: {e}")
        raise

def main():
    """Main function - choose between bot and web based on environment"""
    print("🚀 Starting Network Scanner Bot...")
    
    # For Render.com, we need to run both in the same process
    # Start bot in a separate thread
    import threading
    bot_thread = threading.Thread(target=run_bot, daemon=True)
    bot_thread.start()
    
    # Start Flask app in main thread
    port = int(os.environ.get('PORT', 10000))
    print(f"🌐 Web server starting on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

if __name__ == '__main__':
    main()
