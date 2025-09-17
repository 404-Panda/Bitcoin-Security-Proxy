# Ultra-Fast Bitcoin Mining Proxy - Geek Mode Anti-Cheat
# Lightning-fast forwarding with detailed technical monitoring
# Zero-latency design with comprehensive fraud detection

import socket
import threading
import json
import hashlib
import time
import struct
import ntplib
import requests
from datetime import datetime, timezone
from collections import defaultdict, deque
import statistics

# --------------- CONFIGURATION ---------------
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 3334
POOL_HOST = 'solo.ckpool.org'
POOL_PORT = 3333
BUFFER_SIZE = 16384  # Larger buffers for performance
SOCKET_TIMEOUT = 0.1  # Fast socket operations

# Mining address for pool stats (user configurable)
MINING_ADDRESS = "bc1qtesc50ye5euqtr67sdqke8xdwef6klasc5vx59"  # Hardcoded for testing
POOL_STATS_URL = f"https://solo.ckpool.org/users/{MINING_ADDRESS}" if MINING_ADDRESS else ""
LAST_POOL_STATS_UPDATE = 0  # Track last update time
POOL_STATS_CACHE = {}  # Cache pool stats

# Geek mode settings
GEEK_MODE = True  # Detailed technical output
SHARE_DIFFICULTY_TRACKING = True
EXTRANONCE_FORENSICS = True
TIMING_ANALYSIS = True  # Deep timing attack detection
NTP_VERIFICATION = True  # Use NTP for timing reference

# NTP servers for time verification
NTP_SERVERS = ['pool.ntp.org', 'time.google.com', 'time.cloudflare.com']
ntp_offset = 0  # Offset between local time and NTP time

# File logging
LOGFILE = 'ultra_proxy.log'
CHEAT_LOG = 'suspicious_activity.txt'
GEEK_LOG = 'geek_mode_analysis.txt'
SHARE_LOG = 'share_analysis.txt'
TIMING_LOG = 'timing_analysis.txt'

# Colors for clean output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'

# Ultra-fast data structures
job_templates = {}  # job_id -> job_data
extranonce_registry = {}  # socket_id -> extranonce_info
share_database = deque(maxlen=1000)  # Recent share analysis
timing_database = deque(maxlen=500)  # Timing analysis data
pending_shares = {}  # msg_id -> share_data for tracking responses
pool_difficulty = {}  # miner_addr -> current pool difficulty
miner_profiles = defaultdict(lambda: {
    'connect_time': time.time(),
    'total_shares': 0,
    'accepted_shares': 0,
    'rejected_shares': 0,
    'share_difficulties': deque(maxlen=50),
    'share_submission_times': deque(maxlen=100),
    'job_receive_times': deque(maxlen=50),
    'extranonce1': None,
    'extranonce2_size': 0,
    'last_job_id': None,
    'job_switching_pattern': deque(maxlen=20),
    'timing_profile': deque(maxlen=100),
    'worker_name': 'unknown',
    'last_share_time': 0,
    'avg_share_interval': 0,
    'total_difficulty_submitted': 0,
    'best_share_difficulty': 0,
    'session_hash_rate': 0,
    'current_pool_difficulty': 0  # Track pool-assigned difficulty
})

# Performance counters
perf_stats = {
    'start_time': time.time(),
    'total_bytes_forwarded': 0,
    'total_messages_processed': 0,
    'total_shares_submitted': 0,
    'total_shares_accepted': 0,
    'total_shares_rejected': 0,
    'avg_forward_latency': 0,
    'suspicious_events': 0,
    'blocks_detected': 0,
    'near_misses': 0,
    'active_connections': 0,
    'timing_anomalies': 0,
    'last_ntp_sync': 0,
    'total_difficulty_submitted': 0
}

# Suspicious activity tracking
fraud_detector = {
    'extranonce_anomalies': [],
    'share_difficulty_manipulation': [],
    'timing_attacks': [],
    'job_withholding': [],
    'share_skimming': []
}

# --------------- LOGGING FUNCTIONS ---------------
def log_suspicious_event(event_type, description, data=None, severity='MEDIUM'):
    """Log suspicious events to file with detailed information"""
    timestamp = datetime.now(timezone.utc).isoformat()
    
    event_record = {
        'timestamp': timestamp,
        'type': event_type,
        'description': description,
        'severity': severity,
        'data': data or {}
    }
    
    # Write to suspicious activity log
    with open(CHEAT_LOG, 'a') as f:
        f.write(f"[{timestamp}] {severity}: {event_type}\n")
        f.write(f"Description: {description}\n")
        if data:
            f.write(f"Data: {json.dumps(data, indent=2, default=str)}\n")
        f.write("-" * 80 + "\n")
    
    # Also update fraud detector
    fraud_detector[event_type].append(event_record)
    
    # Console alert
    alert_log(f"{event_type}: {description}", severity)

# --------------- NTP AND TIMING ANALYSIS ---------------
def sync_ntp_time():
    """Synchronize with NTP servers for accurate timing reference"""
    global ntp_offset
    
    for ntp_server in NTP_SERVERS:
        try:
            ntp_client = ntplib.NTPClient()
            response = ntp_client.request(ntp_server, version=3, timeout=2)
            ntp_time = response.tx_time
            local_time = time.time()
            ntp_offset = ntp_time - local_time
            perf_stats['last_ntp_sync'] = local_time
            
            geek_log(f"NTP sync successful with {ntp_server}", {
                'ntp_time': datetime.fromtimestamp(ntp_time, timezone.utc).isoformat(),
                'local_time': datetime.fromtimestamp(local_time, timezone.utc).isoformat(),
                'offset_ms': f"{ntp_offset * 1000:.1f}",
                'accuracy': f"{response.precision:.6f}"
            }, 'TECH')
            return True
            
        except Exception as e:
            geek_log(f"NTP sync failed with {ntp_server}: {e}", category='TECH')
            continue
    
    alert_log("All NTP servers failed - using local time", 'MEDIUM')
    return False

# --------------- POOL STATS INTEGRATION ---------------
def get_accurate_time():
    """Get NTP-corrected time"""
    return time.time() + ntp_offset

def fetch_pool_stats():
    """Fetch mining stats from pool API"""
    global LAST_POOL_STATS_UPDATE, POOL_STATS_CACHE
    
    current_time = time.time()
    
    # Only update every 60 seconds to avoid flooding the pool
    if current_time - LAST_POOL_STATS_UPDATE < 60:
        return POOL_STATS_CACHE
    
    if not POOL_STATS_URL:
        return {}
    
    try:
        response = requests.get(POOL_STATS_URL, timeout=10)
        if response.status_code == 200:
            pool_data = response.json()
            POOL_STATS_CACHE = pool_data
            LAST_POOL_STATS_UPDATE = current_time
            
            geek_log(f"Pool stats updated", {
                'total_hashrate': pool_data.get('hashrate1m', 'unknown'),
                'workers': pool_data.get('workers', 0),
                'bestshare': pool_data.get('bestshare', 0),
                'update_time': datetime.fromtimestamp(current_time).strftime("%H:%M:%S")
            }, 'TECH')
            
            return pool_data
        else:
            clean_log(f"Failed to fetch pool stats: HTTP {response.status_code}", 'WARN')
            return POOL_STATS_CACHE
            
    except Exception as e:
        geek_log(f"Pool stats fetch error: {e}", category='TECH')
        return POOL_STATS_CACHE

def get_worker_stats(worker_name):
    """Get specific worker stats from pool data"""
    pool_data = fetch_pool_stats()
    
    if 'worker' not in pool_data:
        return {}
    
    for worker in pool_data['worker']:
        if worker.get('workername') == worker_name:
            return worker
    
    return {}

def parse_hashrate_string(hashrate_str):
    """Parse hashrate strings like '487G', '1.2T' to GH/s"""
    if not hashrate_str:
        return 0.0
    
    try:
        # Remove any spaces and convert to upper
        hashrate_str = str(hashrate_str).replace(' ', '').upper()
        
        # Extract number and unit
        if hashrate_str[-1] in ['T', 'G', 'M', 'K']:
            unit = hashrate_str[-1]
            number = float(hashrate_str[:-1])
        else:
            unit = 'H'
            number = float(hashrate_str)
        
        # Convert to GH/s
        multipliers = {
            'T': 1000,    # TH/s to GH/s
            'G': 1,       # GH/s
            'M': 0.001,   # MH/s to GH/s
            'K': 0.000001, # KH/s to GH/s
            'H': 0.000000001 # H/s to GH/s
        }
        
        return number * multipliers.get(unit, 1)
        
    except (ValueError, IndexError):
        return 0.0

def setup_mining_address():
    """Setup mining address for pool stats"""
    global MINING_ADDRESS, POOL_STATS_URL
    
    print(f"\n{Colors.CYAN}{Colors.BOLD}Mining Address Setup{Colors.END}")
    print(f"{Colors.BLUE}To get accurate hashrate statistics from the pool, please enter your mining address.{Colors.END}")
    print(f"{Colors.DIM}Example: bc1qtesc50ye5euqtr67sdqke8xdwef6klasc5vx59{Colors.END}")
    
    while True:
        try:
            address = input(f"\n{Colors.CYAN}Enter your mining address (or press Enter to skip): {Colors.END}").strip()
            
            if not address:
                clean_log("Skipping pool stats integration - hashrate will not be available", 'WARN')
                return
            
            # Basic validation - Bitcoin addresses are typically 26-62 characters
            if len(address) < 26 or len(address) > 62:
                print(f"{Colors.RED}Invalid address length. Bitcoin addresses are typically 26-62 characters.{Colors.END}")
                continue
            
            MINING_ADDRESS = address
            POOL_STATS_URL = f"https://{POOL_HOST}/users/{address}"
            
            # Test the API endpoint
            clean_log(f"Testing pool stats API: {POOL_STATS_URL}")
            test_stats = fetch_pool_stats()
            
            if test_stats:
                total_hashrate = test_stats.get('hashrate1m', 'unknown')
                workers = test_stats.get('workers', 0)
                clean_log(f"Pool stats connected successfully!", 'SUCCESS')
                clean_log(f"Total hashrate: {total_hashrate}, Workers: {workers}", 'SUCCESS')
                break
            else:
                print(f"{Colors.RED}Could not fetch stats for this address. Please check the address and try again.{Colors.END}")
                continue
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Setup cancelled{Colors.END}")
            return
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.END}")
            continue
    """Get NTP-corrected time"""
    return time.time() + ntp_offset

def analyze_job_timing(job_data, receive_time):
    """Analyze job timing for manipulation detection"""
    if not TIMING_ANALYSIS:
        return
    
    job_timestamp = int(job_data['ntime'], 16)
    accurate_time = get_accurate_time()
    timestamp_diff = job_timestamp - accurate_time
    
    timing_analysis = {
        'job_id': job_data['job_id'],
        'job_timestamp': job_timestamp,
        'receive_time': receive_time,
        'accurate_time': accurate_time,
        'timestamp_difference': timestamp_diff,
        'is_future': timestamp_diff > 0,
        'is_stale': timestamp_diff < -300,  # More than 5 minutes old
        'age_seconds': accurate_time - job_timestamp
    }
    
    timing_database.append(timing_analysis)
    
    # Check for suspicious timing
    if abs(timestamp_diff) > 7200:  # More than 2 hours difference
        log_suspicious_event('timing_attacks', 
                           f"Extreme timestamp anomaly: Job timestamp off by {timestamp_diff/3600:.1f} hours", 
                           timing_analysis, 'HIGH')
        perf_stats['timing_anomalies'] += 1
        
    elif timestamp_diff > 600:  # More than 10 minutes in future
        log_suspicious_event('timing_attacks', 
                           f"Future timestamp: Job is {timestamp_diff/60:.1f} minutes in the future", 
                           timing_analysis, 'MEDIUM')
        perf_stats['timing_anomalies'] += 1
    
    elif timestamp_diff < -1800:  # More than 30 minutes old
        log_suspicious_event('timing_attacks', 
                           f"Stale job: Job is {-timestamp_diff/60:.1f} minutes old", 
                           timing_analysis, 'MEDIUM')
        perf_stats['timing_anomalies'] += 1
    
    # Log timing details in geek mode
    geek_log(f"Job timing analysis", {
        'job_age_seconds': f"{accurate_time - job_timestamp:.1f}",
        'timestamp_drift': f"{timestamp_diff:.1f}s",
        'is_future_job': timestamp_diff > 0,
        'is_stale_job': timestamp_diff < -300
    }, 'TECH')

def analyze_share_timing(miner_addr, submit_time):
    """Analyze share submission timing patterns"""
    profile = miner_profiles[miner_addr]
    
    if profile['last_share_time'] > 0:
        interval = submit_time - profile['last_share_time']
        profile['share_submission_times'].append(interval)
        
        # Calculate average interval
        if len(profile['share_submission_times']) >= 5:
            profile['avg_share_interval'] = statistics.mean(profile['share_submission_times'])
            
            # Check for suspicious patterns (much more restrictive)
            if interval < 0.005:  # Less than 5ms between shares (extremely suspicious)
                log_suspicious_event('share_skimming', 
                                   f"Extremely rapid shares: {miner_addr} submitted shares {interval*1000:.1f}ms apart", 
                                   {'miner': miner_addr, 'interval_ms': interval*1000}, 'HIGH')
            
            elif interval > profile['avg_share_interval'] * 20:  # Much longer than usual (20x average)
                geek_log(f"Long share interval detected", {
                    'miner': miner_addr,
                    'interval_seconds': f"{interval:.1f}",
                    'average_interval': f"{profile['avg_share_interval']:.1f}",
                    'ratio': f"{interval / profile['avg_share_interval']:.1f}x"
                }, 'TECH')
    
    profile['last_share_time'] = submit_time

def geek_log(msg, data=None, category='TECH'):
    """Detailed technical logging for geek mode"""
    if not GEEK_MODE:
        return
        
    timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    
    # Color-coded geek output
    colors = {
        'TECH': Colors.CYAN,
        'CRYPTO': Colors.MAGENTA,
        'PERF': Colors.BLUE,
        'FRAUD': Colors.RED,
        'SHARE': Colors.GREEN
    }
    
    color = colors.get(category, Colors.CYAN)
    print(f"{color}[GEEK] [{timestamp}] {category}: {msg}{Colors.END}")
    
    if data:
        # Pretty print technical data
        if isinstance(data, dict):
            for k, v in data.items():
                print(f"{color}{Colors.DIM}       {k}: {v}{Colors.END}")
    
    # Log to geek file
    with open(GEEK_LOG, 'a') as f:
        f.write(f"[{timestamp}] {category}: {msg}\n")
        if data:
            f.write(f"Data: {json.dumps(data, indent=2, default=str)}\n")

def alert_log(msg, severity='MEDIUM'):
    """Fast alert logging for suspicious activity"""
    timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
    perf_stats['suspicious_events'] += 1
    
    color = Colors.RED if severity == 'HIGH' else Colors.YELLOW
    print(f"{color}{Colors.BOLD}🚨 [{timestamp}] {msg}{Colors.END}")

def clean_log(msg, level='INFO'):
    """Clean logging for normal operations"""
    timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
    icons = {'INFO': 'ℹ️', 'SUCCESS': '✅', 'WARN': '⚠️', 'ERROR': '❌'}
    colors = {'INFO': Colors.BLUE, 'SUCCESS': Colors.GREEN, 'WARN': Colors.YELLOW, 'ERROR': Colors.RED}
    
    icon = icons.get(level, 'ℹ️')
    color = colors.get(level, Colors.BLUE)
    print(f"{color}{icon} [{timestamp}] {msg}{Colors.END}")

# --------------- CRYPTO UTILITIES (OPTIMIZED) ---------------
def fast_sha256d(data):
    """Optimized double SHA256"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def parse_bits_fast(bits_hex):
    """Fast bits to target conversion - fixed implementation"""
    bits = int(bits_hex, 16)
    exp = (bits >> 24) & 0xff
    mant = bits & 0xffffff
    
    if exp <= 3:
        target = mant >> (8 * (3 - exp))
    else:
        target = mant << (8 * (exp - 3))
    
    # Ensure we have a valid target
    if target == 0:
        target = 1
    
    return target

def calculate_share_difficulty(hash_hex, target):
    """Calculate actual difficulty of submitted share using Bitcoin's truediffone method"""
    # Bitcoin's truediffone constant (same as in C code)
    truediffone = 26959535291011309493156476344723991336010898738574164086137773096960.0
    
    # Convert hash to bytes and treat as little-endian (like le256todouble in C)
    hash_bytes = bytes.fromhex(hash_hex)
    
    # Convert little-endian hash bytes to integer (reverse byte order)
    hash_int = int.from_bytes(hash_bytes, byteorder='little')
    
    if hash_int == 0:
        return float('inf')
    
    # Convert to float and calculate difficulty like cgminer
    hash_as_double = float(hash_int)
    difficulty = truediffone / hash_as_double
    
    geek_log(f"Share difficulty calculation (cgminer method)", {
        'hash_hex': hash_hex[:16] + "...",
        'hash_as_le_int': f"0x{hash_int:x}"[:18] + "...",
        'calculated_difficulty': f"{difficulty:.6f}",
        'method': 'truediffone / le_hash_int'
    }, 'CRYPTO')
    
    return difficulty

def build_merkle_fast(coinbase_hash, branches):
    """Optimized merkle root construction"""
    merkle = bytes.fromhex(coinbase_hash)[::-1]
    for branch in branches:
        merkle = fast_sha256d(merkle + bytes.fromhex(branch)[::-1])
    return merkle[::-1].hex()

# --------------- EXTRANONCE FORENSICS ---------------
def analyze_extranonce_allocation(extranonce1, extranonce2_size, miner_addr):
    """Deep analysis of extranonce allocation patterns"""
    profile = miner_profiles[miner_addr]
    
    if EXTRANONCE_FORENSICS:
        # Check for extranonce1 changes (highly suspicious)
        if profile['extranonce1'] and profile['extranonce1'] != extranonce1:
            log_suspicious_event('extranonce_anomalies', 
                               f"ExtraNonce1 changed for {miner_addr}", 
                               {
                                   'miner': miner_addr,
                                   'old_extranonce1': profile['extranonce1'],
                                   'new_extranonce1': extranonce1,
                                   'time_since_connect': time.time() - profile['connect_time']
                               }, 'HIGH')
        
        # Analyze nonce space allocation
        extranonce1_bytes = len(bytes.fromhex(extranonce1))
        miner_controlled_bytes = 4 + extranonce2_size  # nonce + extranonce2
        total_search_space_bits = 32 + (extranonce2_size * 8)  # nonce bits + extranonce2 bits
        
        geek_log(f"Nonce space analysis for {miner_addr}", {
            'pool_assigned_extranonce1': extranonce1,
            'extranonce1_bytes': extranonce1_bytes,
            'miner_controlled_extranonce2_bytes': extranonce2_size,
            'miner_controlled_nonce_bytes': 4,
            'total_miner_controlled_bytes': miner_controlled_bytes,
            'miner_search_space': f"2^{total_search_space_bits}",
            'extranonce2_quality': 'generous' if extranonce2_size >= 6 else 'adequate' if extranonce2_size >= 4 else 'limited'
        }, 'CRYPTO')
        
        # Check for suspiciously small miner-controlled nonce space
        if extranonce2_size < 4:  # Less than 4 bytes extranonce2
            log_suspicious_event('extranonce_anomalies', 
                               f"Limited nonce space: {miner_addr} only has {extranonce2_size} bytes extranonce2", 
                               {
                                   'miner': miner_addr,
                                   'extranonce2_bytes': extranonce2_size,
                                   'total_miner_space': f"2^{total_search_space_bits}",
                                   'potential_issue': 'Pool may be limiting mining efficiency'
                               }, 'MEDIUM')
        
        elif extranonce2_size >= 8:  # 8+ bytes is very generous
            geek_log(f"Generous nonce space allocation", {
                'miner': miner_addr,
                'extranonce2_bytes': extranonce2_size,
                'search_space_quality': 'excellent',
                'mining_efficiency': 'unrestricted'
            }, 'CRYPTO')
    
    profile['extranonce1'] = extranonce1
    profile['extranonce2_size'] = extranonce2_size

# --------------- SHARE DIFFICULTY ANALYSIS ---------------
# --------------- SHARE DIFFICULTY ANALYSIS ---------------
def analyze_share_submission(header_hash, target, job_data, submit_params, miner_addr, msg_id):
    """Comprehensive share analysis - understanding pool vs network targets"""
    # Convert hash to integer for comparison with target
    hash_bytes = bytes.fromhex(header_hash)
    hash_int = int.from_bytes(hash_bytes, byteorder='big')
    
    # Calculate network difficulty (from job's nbits)
    network_difficulty = 0x00000000FFFF0000000000000000000000000000000000000000000000000000 / target
    
    # Calculate share difficulty (what the miner actually achieved)
    share_difficulty = calculate_share_difficulty(header_hash, target)
    
    profile = miner_profiles[miner_addr]
    profile['share_difficulties'].append(share_difficulty)
    profile['total_difficulty_submitted'] += share_difficulty
    
    # Update best share
    if share_difficulty > profile['best_share_difficulty']:
        profile['best_share_difficulty'] = share_difficulty
        geek_log(f"New best share for {miner_addr}", {
            'difficulty': f"{share_difficulty:.6f}",
            'previous_best': f"{profile['best_share_difficulty']:.6f}"
        }, 'SHARE')
    
    # Share analysis
    share_analysis = {
        'timestamp': time.time(),
        'miner': miner_addr,
        'job_id': job_data['job_id'],
        'header_hash': header_hash,
        'network_target': hex(target),
        'network_difficulty': network_difficulty,
        'share_difficulty': share_difficulty,
        'would_be_block': hash_int <= target,  # Only if it meets network target
        'nonce': submit_params[4],
        'extranonce2': submit_params[2],
        'msg_id': msg_id,
        'hash_int': hash_int
    }
    
    share_database.append(share_analysis)
    
    # Store pending share for response tracking
    pending_shares[msg_id] = {
        'miner': miner_addr,
        'difficulty': share_difficulty,
        'submit_time': time.time(),
        'share_analysis': share_analysis
    }
    
    # Update global stats
    perf_stats['total_difficulty_submitted'] += share_difficulty
    
    if SHARE_DIFFICULTY_TRACKING:
        geek_log(f"Share analysis for {miner_addr}", {
            'share_difficulty': f"{share_difficulty:.6f}",
            'network_difficulty': f"{network_difficulty:.0f}",
            'hash_int': f"0x{hash_int:064x}",
            'network_target': f"0x{target:064x}",
            'note': 'Pool has separate easier share target',
            'msg_id': msg_id
        }, 'SHARE')
    
    # Check for actual block (network target)
    if hash_int <= target:
        perf_stats['blocks_detected'] += 1
        clean_log(f"🎉 BLOCK FOUND BY {miner_addr}! Difficulty: {share_difficulty:.0f}", 'SUCCESS')
        
        # Log detailed block info
        with open('found_blocks.txt', 'a') as f:
            f.write(f"=== BLOCK FOUND ===\n")
            f.write(f"Timestamp: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"Miner: {miner_addr}\n")
            f.write(f"Block Hash: {header_hash}\n")
            f.write(f"Hash Int: 0x{hash_int:064x}\n")
            f.write(f"Network Target: 0x{target:064x}\n")
            f.write(f"Share Difficulty: {share_difficulty}\n")
            f.write(f"Job ID: {job_data['job_id']}\n")
            f.write(f"Nonce: {submit_params[4]}\n")
            f.write(f"ExtraNonce2: {submit_params[2]}\n\n")
        
        return True
    
    # Near-miss detection for network target
    miss_ratio = hash_int / target
    if 1.0 < miss_ratio < 1.05:
        perf_stats['near_misses'] += 1
        geek_log(f"Near-miss detected from {miner_addr}", {
            'how_close': f"{(miss_ratio - 1) * 100:.3f}% over network target",
            'share_difficulty': f"{share_difficulty:.6f}",
            'note': 'Close to finding a block!'
        }, 'CRYPTO')
    
    return False

def handle_share_response(msg, miner_addr):
    """Handle pool response to share submission - extract actual difficulty if available"""
    msg_id = msg.get('id')
    if not msg_id or msg_id not in pending_shares:
        return
    
    share_info = pending_shares[msg_id]
    result = msg.get('result')
    error = msg.get('error')
    
    # Update miner profile
    profile = miner_profiles[share_info['miner']]
    
    if result is True and error is None:
        # Share accepted
        profile['accepted_shares'] += 1
        perf_stats['total_shares_accepted'] += 1
        
        # Use the pool-set difficulty (not calculated)
        pool_diff = share_info['pool_difficulty']
        profile['total_difficulty_submitted'] += pool_diff
        perf_stats['total_difficulty_submitted'] += pool_diff
        
        if pool_diff > profile['best_share_difficulty']:
            profile['best_share_difficulty'] = pool_diff
        
        clean_log(f"✅ SHARE ACCEPTED from {share_info['miner']} | Pool Diff: {pool_diff}")
        
        geek_log(f"Share accepted", {
            'miner': share_info['miner'],
            'pool_difficulty': pool_diff,
            'response_time': f"{(time.time() - share_info['submit_time']) * 1000:.1f}ms",
            'msg_id': msg_id,
            'note': 'Using pool-assigned difficulty'
        }, 'SHARE')
        
    else:
        # Share rejected
        profile['rejected_shares'] += 1
        perf_stats['total_shares_rejected'] += 1
        
        # Better error message parsing
        if error and isinstance(error, list) and len(error) > 1:
            error_msg = str(error[1])
        elif error and isinstance(error, str):
            error_msg = error
        elif result is False:
            error_msg = "Share rejected (result: false)"
        else:
            error_msg = "Unknown rejection reason"
        
        clean_log(f"❌ SHARE REJECTED from {share_info['miner']} | Error: {error_msg}")
        
        # Only log as suspicious if it's not a common rejection reason
        common_rejections = ['stale', 'duplicate', 'low difficulty', 'job not found']
        is_suspicious = not any(reason in error_msg.lower() for reason in common_rejections)
        
        if is_suspicious:
            log_suspicious_event('share_difficulty_manipulation', 
                               f"Share rejected: {error_msg}", 
                               {
                                   'miner': share_info['miner'],
                                   'pool_difficulty': share_info['pool_difficulty'],
                                   'error': error_msg,
                                   'msg_id': msg_id
                               }, 'LOW')
        else:
            # Just log normal rejections in geek mode
            geek_log(f"Normal share rejection", {
                'miner': share_info['miner'],
                'error': error_msg,
                'msg_id': msg_id,
                'note': 'Common rejection - not suspicious'
            }, 'SHARE')
    
    # Calculate session hash rate using pool difficulty
    if len(profile['share_difficulties']) > 5:
        session_time = time.time() - profile['connect_time']
        # Hash rate = (total_difficulty * 2^32) / time_in_seconds
        if session_time > 0:
            profile['session_hash_rate'] = (profile['total_difficulty_submitted'] * (2**32)) / session_time
    
    # Remove from pending
    del pending_shares[msg_id]

# --------------- HIGH-PERFORMANCE MESSAGE HANDLERS ---------------
def handle_notify_fast(msg):
    """Ultra-fast job notification handling with timing analysis"""
    start_time = time.perf_counter()
    receive_time = get_accurate_time()
    
    params = msg.get('params', [])
    if len(params) < 8:
        return
    
    job_id = params[0]
    job_data = {
        'job_id': job_id,
        'prevhash': params[1],
        'coinb1': params[2],
        'coinb2': params[3],
        'merkle_branch': params[4],
        'version': params[5],
        'nbits': params[6],
        'ntime': params[7],
        'clean_jobs': params[8] if len(params) > 8 else False,
        'receive_time': receive_time
    }
    
    job_templates[job_id] = job_data
    target = parse_bits_fast(job_data['nbits'])
    difficulty = 0x00000000FFFF0000000000000000000000000000000000000000000000000000 / target
    
    # Analyze job timing for manipulation
    analyze_job_timing(job_data, receive_time)
    
    clean_log(f"📋 New job {job_id[:8]}... | Network Difficulty: {difficulty:.0f} | Merkle branches: {len(job_data['merkle_branch'])}")
    
    if GEEK_MODE:
        job_timestamp = int(job_data['ntime'], 16)
        job_age = receive_time - job_timestamp
        
        geek_log(f"Job notification processed", {
            'job_id': job_id,
            'network_difficulty': f"{difficulty:.0f}",
            'clean_jobs': job_data['clean_jobs'],
            'coinbase_size': len(job_data['coinb1']) + len(job_data['coinb2']),
            'merkle_branches': len(job_data['merkle_branch']),
            'job_timestamp': datetime.fromtimestamp(job_timestamp, timezone.utc).strftime("%H:%M:%S"),
            'job_age_seconds': f"{job_age:.1f}",
            'processing_time_us': f"{(time.perf_counter() - start_time) * 1000000:.1f}"
        }, 'TECH')

def handle_set_difficulty(msg, addr):
    """Handle pool setting share difficulty for miner"""
    params = msg.get('params', [])
    if len(params) < 1:
        return
    
    share_difficulty = params[0]
    profile = miner_profiles[addr]
    profile['current_pool_difficulty'] = share_difficulty
    
    clean_log(f"🎯 Pool set difficulty for {addr}: {share_difficulty}")
    
    geek_log(f"Pool difficulty set", {
        'miner': addr,
        'share_difficulty': share_difficulty,
        'worker': profile['worker_name']
    }, 'TECH')

def handle_submit_fast(msg, sock, addr):
    """Ultra-fast share submission handling - passive monitoring only"""
    start_time = time.perf_counter()
    submit_time = get_accurate_time()
    
    params = msg.get('params', [])
    if len(params) < 5:
        return
    
    worker, job_id, extranonce2, ntime, nonce = params[:5]
    version_hex = params[5] if len(params) > 5 else None
    msg_id = msg.get('id')
    
    # Update counters
    perf_stats['total_shares_submitted'] += 1
    profile = miner_profiles[addr]
    profile['total_shares'] += 1
    profile['worker_name'] = worker
    
    # Analyze share timing patterns
    analyze_share_timing(addr, submit_time)
    
    # Get cached data for basic analysis
    template = job_templates.get(job_id)
    socket_id = id(sock)
    extranonce_info = extranonce_registry.get(socket_id)
    
    # Use pool-set difficulty (not calculated difficulty)
    pool_diff = profile.get('current_pool_difficulty', 0)
    
    if template:
        job_age = submit_time - template.get('receive_time', submit_time)
    else:
        job_age = 0
    
    # Simple logging without hash calculations
    clean_log(f"📤 SHARE from {addr} | Worker: {worker} | Job: {job_id[:8]}... | Nonce: {nonce} | Pool Diff: {pool_diff}")
    
    # Store share for response tracking (without calculated difficulty)
    pending_shares[msg_id] = {
        'miner': addr,
        'pool_difficulty': pool_diff,
        'submit_time': submit_time,
        'job_id': job_id,
        'nonce': nonce,
        'extranonce2': extranonce2
    }
    
    # Detailed geek analysis
    if GEEK_MODE:
        geek_log(f"Share submission (passive monitoring)", {
            'worker': worker,
            'pool_set_difficulty': pool_diff,
            'job_age_seconds': f"{job_age:.1f}",
            'ntime': ntime,
            'extranonce2': extranonce2,
            'nonce': nonce,
            'version': version_hex if version_hex else 'from_job',
            'submission_interval': f"{submit_time - profile['last_share_time']:.1f}s" if profile['last_share_time'] > 0 else "first",
            'msg_id': msg_id,
            'note': 'Difficulty will be confirmed by pool response'
        }, 'SHARE')
    
    # Check for timing anomalies in ntime
    if template:
        submit_ntime = int(ntime, 16)
        current_time = submit_time
        ntime_diff = submit_ntime - current_time
        
        if abs(ntime_diff) > 3600:  # ntime more than 1 hour off
            log_suspicious_event('timing_attacks', 
                               f"ntime anomaly: {addr} submitted ntime {ntime_diff/3600:.1f} hours off", 
                               {
                                   'miner': addr,
                                   'ntime_hex': ntime,
                                   'ntime_timestamp': submit_ntime,
                                   'current_timestamp': current_time,
                                   'difference_hours': ntime_diff/3600
                               }, 'HIGH')
    
    # Log to share analysis file (without calculated difficulty)
    with open(SHARE_LOG, 'a') as f:
        f.write(f"{datetime.fromtimestamp(submit_time, timezone.utc).isoformat()},{addr},{worker},{job_id},{nonce},{pool_diff:.6f},{job_age:.1f},pending,{msg_id}\n")
    
    processing_time = (time.perf_counter() - start_time) * 1000000
    
    if GEEK_MODE and processing_time > 100:
        geek_log(f"Share processing completed", {
            'processing_time_us': f"{processing_time:.1f}",
            'total_shares_this_session': profile['total_shares'],
            'note': 'No hash calculation - pure passthrough monitoring'
        }, 'PERF')

def handle_subscribe_fast(msg, sock, addr):
    """Fast subscription handling"""
    result = msg.get('result')
    if not result or len(result) < 2:
        return
    
    socket_id = id(sock)
    extranonce1 = result[1]
    extranonce2_size = result[2] if len(result) > 2 else 4
    
    # Store extranonce data
    extranonce_registry[socket_id] = {
        'extranonce1': extranonce1,
        'extranonce2_size': extranonce2_size,
        'assigned_time': time.time()
    }
    
    clean_log(f"Miner {addr} subscribed | ExtraNonce1: {extranonce1}")
    
    # Forensic analysis
    analyze_extranonce_allocation(extranonce1, extranonce2_size, addr)

# --------------- ULTRA-LOW LATENCY FORWARDING ---------------
def lightning_forward(src, dst, direction, addr):
    """Ultra-low latency message forwarding"""
    buffer = b''
    message_count = 0
    
    # Set socket options for performance
    src.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    dst.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    
    while True:
        try:
            # Non-blocking receive with larger buffer
            data = src.recv(BUFFER_SIZE)
            if not data:
                break
                
            buffer += data
            perf_stats['total_bytes_forwarded'] += len(data)
            
            # Process complete messages
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                line = line.strip()
                if not line:
                    continue
                
                message_count += 1
                forward_start = time.perf_counter()
                
                # Minimal processing for anti-cheat
                try:
                    msg = json.loads(line.decode('utf-8', errors='ignore'))
                    perf_stats['total_messages_processed'] += 1
                    
                    # Fast message analysis
                    if direction == 'pool_to_miner':
                        if msg.get('method') == 'mining.notify':
                            handle_notify_fast(msg)
                        elif msg.get('method') == 'mining.set_difficulty':
                            handle_set_difficulty(msg, addr)
                        elif msg.get('id') == 2:  # subscribe response
                            handle_subscribe_fast(msg, dst, addr)
                        elif 'result' in msg and msg.get('id'):  # Share response
                            handle_share_response(msg, addr)
                    
                    elif direction == 'miner_to_pool':
                        if msg.get('method') == 'mining.submit':
                            handle_submit_fast(msg, src, addr)
                        elif msg.get('method') == 'mining.authorize':
                            worker = msg.get('params', [None])[0]
                            if worker:
                                miner_profiles[addr]['worker_name'] = worker
                                clean_log(f"Worker authorized: {worker} from {addr}")
                
                except (json.JSONDecodeError, KeyError):
                    pass  # Ignore malformed messages - keep forwarding fast
                
                # Forward immediately (minimal latency)
                dst.sendall(line + b'\n')
                
                # Track forwarding performance
                forward_time = (time.perf_counter() - forward_start) * 1000000
                if forward_time > 50:  # Log if forwarding takes > 50 microseconds
                    geek_log(f"Slow forward detected", {
                        'direction': direction,
                        'forward_time_us': f"{forward_time:.1f}",
                        'message_size': len(line)
                    }, 'PERF')
                
        except socket.timeout:
            continue
        except Exception:
            break
    
    # Cleanup
    try:
        src.close()
        dst.close()
    except:
        pass

# --------------- CONNECTION HANDLER ---------------
def handle_miner_connection(client_sock, addr):
    """Handle miner connection with maximum performance"""
    addr_str = f"{addr[0]}:{addr[1]}"
    perf_stats['active_connections'] += 1
    
    try:
        clean_log(f"Miner connected: {addr_str}", 'SUCCESS')
        
        # Ultra-fast pool connection
        pool_sock = socket.create_connection((POOL_HOST, POOL_PORT))
        pool_sock.settimeout(SOCKET_TIMEOUT)
        client_sock.settimeout(SOCKET_TIMEOUT)
        
        # Start high-performance forwarding threads
        pool_to_miner = threading.Thread(
            target=lightning_forward,
            args=(pool_sock, client_sock, 'pool_to_miner', addr_str),
            daemon=True
        )
        
        miner_to_pool = threading.Thread(
            target=lightning_forward,
            args=(client_sock, pool_sock, 'miner_to_pool', addr_str),
            daemon=True
        )
        
        pool_to_miner.start()
        miner_to_pool.start()
        
        # Wait for connection to end
        pool_to_miner.join()
        miner_to_pool.join()
        
    except Exception as e:
        geek_log(f"Connection error for {addr_str}: {e}", category='TECH')
    finally:
        perf_stats['active_connections'] -= 1
        clean_log(f"Miner disconnected: {addr_str}", 'WARN')
        
        # Cleanup
        socket_id = id(client_sock)
        if socket_id in extranonce_registry:
            del extranonce_registry[socket_id]

# --------------- PERFORMANCE MONITOR ---------------
def performance_monitor():
    """Background performance and security monitoring with enhanced metrics"""
    last_stats_time = time.time()
    last_message_count = 0
    last_share_count = 0
    
    while True:
        time.sleep(30)
        
        current_time = time.time()
        uptime = int(current_time - perf_stats['start_time'])
        time_delta = current_time - last_stats_time
        
        # Calculate performance metrics
        messages_per_second = (perf_stats['total_messages_processed'] - last_message_count) / time_delta
        shares_per_minute = (perf_stats['total_shares_submitted'] - last_share_count) / time_delta * 60
        
        last_message_count = perf_stats['total_messages_processed']
        last_share_count = perf_stats['total_shares_submitted']
        last_stats_time = current_time
        
        # Sync NTP periodically
        if current_time - perf_stats['last_ntp_sync'] > 3600:  # Every hour
            if NTP_VERIFICATION:
                sync_ntp_time()
        
        # Display comprehensive stats
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*80}")
        print(f"⛏️  ULTRA-FAST MINING PROXY - COMPREHENSIVE MONITOR")
        print(f"{'='*80}{Colors.END}")
        
        # Performance metrics
        print(f"{Colors.BLUE}📊 PERFORMANCE: {uptime//3600}h {(uptime%3600)//60}m {uptime%60}s | "
              f"Active: {perf_stats['active_connections']} | "
              f"Msg/s: {messages_per_second:.1f} | "
              f"Shares/min: {shares_per_minute:.1f}{Colors.END}")
        
        # Enhanced processing stats with acceptance rate
        total_shares = perf_stats['total_shares_submitted']
        if total_shares > 0:
            accept_rate = perf_stats['total_shares_accepted'] / total_shares
            reject_rate = perf_stats['total_shares_rejected'] / total_shares
            accept_color = Colors.GREEN if accept_rate > 0.95 else Colors.YELLOW if accept_rate > 0.90 else Colors.RED
            
            print(f"{Colors.GREEN}📈 SHARES: {total_shares} submitted | "
                  f"{accept_color}Accept: {perf_stats['total_shares_accepted']} ({accept_rate:.1%}){Colors.END} | "
                  f"{Colors.RED}Reject: {perf_stats['total_shares_rejected']} ({reject_rate:.1%}){Colors.END} | "
                  f"Blocks: {perf_stats['blocks_detected']} | "
                  f"Near-misses: {perf_stats['near_misses']}")
            
            # Total difficulty submitted
            print(f"{Colors.MAGENTA}💎 DIFFICULTY: Total submitted: {perf_stats['total_difficulty_submitted']:.0f}{Colors.END}")
        
        # Timing analysis summary
        if TIMING_ANALYSIS and len(timing_database) > 0:
            recent_timings = list(timing_database)[-10:]  # Last 10 jobs
            avg_job_age = statistics.mean([t['age_seconds'] for t in recent_timings])
            future_jobs = sum(1 for t in recent_timings if t['is_future'])
            stale_jobs = sum(1 for t in recent_timings if t['is_stale'])
            
            timing_color = Colors.GREEN if perf_stats['timing_anomalies'] == 0 else Colors.YELLOW
            print(f"{timing_color}🕐 TIMING: Avg job age: {avg_job_age:.1f}s | "
                  f"Future jobs: {future_jobs} | "
                  f"Stale jobs: {stale_jobs} | "
                  f"Anomalies: {perf_stats['timing_anomalies']}{Colors.END}")
            
            # NTP status
            ntp_age = current_time - perf_stats['last_ntp_sync']
            ntp_color = Colors.GREEN if ntp_age < 3600 else Colors.YELLOW
            print(f"{ntp_color}🌐 NTP: Last sync {ntp_age/60:.0f}m ago | "
                  f"Offset: {ntp_offset*1000:.1f}ms{Colors.END}")
        
        # Miner summary with pool stats integration
        if miner_profiles:
            active_miners = [addr for addr, profile in miner_profiles.items() 
                           if current_time - profile['connect_time'] < uptime]
            
            print(f"{Colors.CYAN}⛏️  MINERS: {len(active_miners)} active{Colors.END}")
            
            # Get pool stats for enhanced display
            pool_data = fetch_pool_stats() if POOL_STATS_URL else {}
            
            if pool_data:
                total_pool_hashrate = pool_data.get('hashrate1m', 'unknown')
                print(f"{Colors.MAGENTA}🌊 POOL STATS: Total hashrate: {total_pool_hashrate} | Workers: {pool_data.get('workers', 0)} | Best share: {pool_data.get('bestshare', 0):.0f}{Colors.END}")
            
            # Show top miners by share count with pool hashrate data
            top_miners = sorted(miner_profiles.items(), 
                              key=lambda x: x[1]['total_shares'], reverse=True)[:3]
            
            for addr, profile in top_miners:
                if profile['total_shares'] > 0:
                    session_time = current_time - profile['connect_time']
                    shares_per_hour = profile['total_shares'] / (session_time / 3600) if session_time > 0 else 0
                    accept_rate = profile['accepted_shares'] / profile['total_shares'] if profile['total_shares'] > 0 else 0
                    
                    # Try to get pool hashrate for this worker
                    worker_stats = get_worker_stats(profile['worker_name']) if POOL_STATS_URL else {}
                    pool_hashrate_str = "unknown"
                    
                    if worker_stats:
                        pool_hashrate_1m = worker_stats.get('hashrate1m', '')
                        if pool_hashrate_1m:
                            pool_hashrate_gh = parse_hashrate_string(pool_hashrate_1m)
                            pool_hashrate_str = f"{pool_hashrate_gh:.1f}GH/s"
                        
                        # Also show pool's best share for this worker
                        pool_best_share = worker_stats.get('bestshare', 0)
                        if pool_best_share > profile['best_share_difficulty']:
                            profile['best_share_difficulty'] = pool_best_share
                    else:
                        # If no pool stats, show that it's not available
                        pool_hashrate_str = "no pool data"
                    
                    print(f"{Colors.DIM}   {addr}: {profile['total_shares']} shares | "
                          f"{shares_per_hour:.1f}/hr | "
                          f"{accept_rate:.1%} accept | "
                          f"Best: {profile['best_share_difficulty']:.1f} | "
                          f"Rate: {pool_hashrate_str} | "
                          f"Worker: {profile['worker_name']}{Colors.END}")
                    
                    # Show additional pool stats if available
                    if worker_stats and GEEK_MODE:
                        geek_log(f"Pool stats for {profile['worker_name']}", {
                            'hashrate_1m': worker_stats.get('hashrate1m', 'unknown'),
                            'hashrate_5m': worker_stats.get('hashrate5m', 'unknown'),
                            'hashrate_1d': worker_stats.get('hashrate1d', 'unknown'),
                            'pool_shares': worker_stats.get('shares', 0),
                            'last_pool_share': worker_stats.get('lastshare', 0),
                            'best_ever': worker_stats.get('bestever', 0)
                        }, 'SHARE')
        
        # Security status
        if perf_stats['suspicious_events'] > 0:
            print(f"{Colors.RED}🚨 SECURITY: {perf_stats['suspicious_events']} suspicious events detected{Colors.END}")
            print(f"{Colors.YELLOW}   Check {CHEAT_LOG} for detailed analysis{Colors.END}")
        else:
            print(f"{Colors.GREEN}✅ SECURITY: All systems normal - no suspicious activity{Colors.END}")
        
        print(f"{Colors.CYAN}{'='*80}{Colors.END}\n")

# --------------- MAIN ENTRY POINT ---------------
def main():
    print(f"{Colors.BOLD}{Colors.CYAN}")
    print("⚡" + "="*70)
    print("  ULTRA-FAST BITCOIN MINING PROXY - TIMING FORENSICS")
    print("  Lightning Performance + NTP Timing + Anti-Cheat Detection")
    print("="*74)
    print(f"{Colors.END}")
    
    clean_log(f"🚀 Ultra-fast proxy starting on port {LISTEN_PORT}")
    clean_log(f"🎯 Target pool: {POOL_HOST}:{POOL_PORT}")
    clean_log(f"⚡ Geek mode: {GEEK_MODE} | Share tracking: {SHARE_DIFFICULTY_TRACKING}")
    clean_log(f"🛡️ Extranonce forensics: {EXTRANONCE_FORENSICS}")
    clean_log(f"🕐 Timing analysis: {TIMING_ANALYSIS} | NTP verification: {NTP_VERIFICATION}")
    
    # Initialize log files
    with open(CHEAT_LOG, 'w') as f:
        f.write(f"=== SUSPICIOUS ACTIVITY LOG - {datetime.now(timezone.utc).isoformat()} ===\n\n")
    
    # Initialize NTP synchronization
    if NTP_VERIFICATION:
        clean_log("🌐 Synchronizing with NTP servers...")
        if sync_ntp_time():
            clean_log("✅ NTP synchronization successful", 'SUCCESS')
        else:
            clean_log("⚠️ NTP synchronization failed - using local time", 'WARN')
    
    # Create share analysis log header
    with open(SHARE_LOG, 'w') as f:
        f.write("timestamp,miner_addr,worker,job_id,nonce,share_difficulty,job_age_seconds,is_block,msg_id\n")
    
    # Start performance monitor
    monitor_thread = threading.Thread(target=performance_monitor, daemon=True)
    monitor_thread.start()
    
    try:
        # High-performance server setup
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # Disable Nagle
        server.bind((LISTEN_HOST, LISTEN_PORT))
        server.listen(20)  # Higher backlog for performance
        
        clean_log(f"✅ Lightning-fast proxy listening on {LISTEN_HOST}:{LISTEN_PORT}", 'SUCCESS')
        clean_log("⚡ Ready for ultra-low latency mining with timing forensics...")
        
        while True:
            try:
                client_sock, addr = server.accept()
                
                # Handle each connection in separate thread for maximum performance
                connection_thread = threading.Thread(
                    target=handle_miner_connection,
                    args=(client_sock, addr),
                    daemon=True
                )
                connection_thread.start()
                
            except KeyboardInterrupt:
                clean_log("🛑 Shutdown requested", 'WARN')
                break
            except Exception as e:
                geek_log(f"Accept error: {e}", category='TECH')
                
    except Exception as e:
        clean_log(f"Server error: {e}", 'ERROR')
    finally:
        clean_log("👋 Ultra-fast proxy shutting down...")
        if perf_stats['suspicious_events'] > 0:
            print(f"{Colors.RED}⚠️  Check {CHEAT_LOG} for suspicious activity details{Colors.END}")
        if perf_stats['timing_anomalies'] > 0:
            print(f"{Colors.YELLOW}🕐 Check {TIMING_LOG} for timing analysis details{Colors.END}")
        
        # Final summary
        total_shares = perf_stats['total_shares_submitted']
        if total_shares > 0:
            accept_rate = perf_stats['total_shares_accepted'] / total_shares
            print(f"{Colors.GREEN}📊 Final Stats: {total_shares} shares | "
                  f"{perf_stats['total_shares_accepted']} accepted ({accept_rate:.1%}) | "
                  f"Total difficulty: {perf_stats['total_difficulty_submitted']:.0f}{Colors.END}")

if __name__ == '__main__':
    try:
        main()
    except ImportError as e:
        if 'ntplib' in str(e):
            print(f"{Colors.RED}❌ ntplib not installed. Install with: pip install ntplib{Colors.END}")
            print(f"{Colors.YELLOW}⚠️  Continuing without NTP synchronization...{Colors.END}")
            NTP_VERIFICATION = False
            main()
        else:
            raise
