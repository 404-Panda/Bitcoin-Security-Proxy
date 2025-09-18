# ⚡ Ultra-Fast Bitcoin Mining Proxy

## Lightning-Fast Forwarding with Comprehensive Timing Forensics & Anti-Cheat Detection

A high-performance Bitcoin mining proxy designed for ultra-low latency forwarding combined with sophisticated timing analysis and fraud detection capabilities. This proxy provides transparent passthrough mining while monitoring for suspicious activities and timing anomalies.

---

## 🚀 Key Features

### Performance
- **Ultra-Low Latency**: Optimized forwarding with microsecond-level timing analysis
- **Zero Mining Interference**: Pure passthrough design - doesn't modify mining operations
- **High Throughput**: Handles multiple concurrent miners with minimal overhead
- **TCP_NODELAY**: Disables Nagle algorithm for immediate packet forwarding

### Security & Monitoring
- **NTP Time Synchronization**: Accurate timing reference for anomaly detection
- **Extranonce Forensics**: Deep analysis of nonce space allocation patterns
- **Share Difficulty Tracking**: Monitors pool-assigned vs calculated difficulties  
- **Timing Attack Detection**: Identifies suspicious timestamp manipulation
- **Job Withholding Detection**: Tracks job switching and submission patterns
- **Real-time Fraud Alerts**: Immediate notification of suspicious activities

### Analytics
- **Pool Stats Integration**: Fetches real-time hashrate data from pool APIs
- **Comprehensive Logging**: Detailed technical logs for geek-mode analysis
- **Performance Metrics**: Real-time monitoring of forwarding performance
- **Block Detection**: Celebrates successful block discoveries
- **Near-Miss Tracking**: Identifies shares close to network difficulty

---

## 🔧 How It Works

### Architecture

```
[Miner] ↔ [Ultra-Fast Proxy] ↔ [Mining Pool]
              ↓
         [Monitoring & Analysis]
              ↓
    [Logs, Alerts, Statistics]
```

### Core Components

1. **Lightning Forwarder**: 
   - Receives messages from miners and forwards to pool
   - Processes pool responses back to miners
   - Maintains separate threads for each direction to minimize latency

2. **Message Analyzer**:
   - Parses JSON-RPC mining protocol messages
   - Extracts job notifications, share submissions, and pool responses
   - Performs real-time analysis without blocking forwarding

3. **Timing Engine**:
   - Synchronizes with NTP servers for accurate time reference
   - Analyzes job timestamps for manipulation attempts
   - Tracks share submission intervals and patterns

4. **Security Monitor**:
   - Detects extranonce anomalies and nonce space manipulation
   - Identifies timing attacks and stale job submissions
   - Monitors for share skimming and job withholding

5. **Pool Integration**:
   - Connects to pool APIs for real-time statistics
   - Correlates proxy data with official pool metrics
   - Provides accurate hashrate reporting

### Detection Methods

#### Timing Analysis
- **Job Age Verification**: Compares job timestamps with NTP-synchronized time
- **Submission Interval Analysis**: Identifies unnaturally rapid or delayed shares
- **Clock Drift Detection**: Monitors for timestamp manipulation attempts

#### Extranonce Forensics
- **Nonce Space Allocation**: Analyzes miner-controlled vs pool-controlled nonce space
- **ExtraNonce1 Monitoring**: Detects suspicious changes in pool-assigned values
- **Search Space Quality**: Evaluates adequacy of allocated mining space

#### Share Analysis
- **Difficulty Correlation**: Compares calculated vs pool-assigned share difficulties
- **Pattern Recognition**: Identifies unusual submission patterns
- **Response Tracking**: Monitors pool acceptance/rejection rates

---

## 📋 Requirements

### System Requirements
- Python 3.7+
- Network connectivity to target mining pool
- Optional: Internet access for NTP synchronization and pool stats

### Python Dependencies
```bash
pip install ntplib requests
```

### Pool Compatibility
- Stratum V1 mining protocol
- Tested with major pools (solo.ckpool.org, etc.)
- JSON-RPC message format support

---

## 🛠️ Installation & Setup

### 1. Download and Install
```bash
git clone <repository-url>
cd ultra-fast-mining-proxy
pip install ntplib requests
```

### 2. Configuration
Edit the configuration section in the script:

```python
# Basic Configuration
LISTEN_HOST = '0.0.0.0'        # Listen on all interfaces
LISTEN_PORT = 3334             # Proxy listening port
POOL_HOST = 'solo.ckpool.org'  # Target mining pool
POOL_PORT = 3333               # Pool port

# Optional: Your mining address for pool stats
MINING_ADDRESS = "1YourBitcoinAddressHere"

# Feature Toggles
GEEK_MODE = True               # Detailed technical logging
SHARE_DIFFICULTY_TRACKING = True
EXTRANONCE_FORENSICS = True
TIMING_ANALYSIS = True
NTP_VERIFICATION = True
```

### 3. Launch the Proxy
```bash
python ultra_mining_proxy.py
```

The proxy will:
- Synchronize with NTP servers
- Start listening on the configured port
- Display real-time status and statistics

---

## 🔌 Connecting Your Miners

### Point Miners to Proxy
Configure your mining software to connect to the proxy instead of directly to the pool:

**Instead of:**
```
stratum+tcp://solo.ckpool.org:3333
```

**Use:**
```
stratum+tcp://YOUR_PROXY_IP:3334
```

### Miner Configuration Examples

#### CGMiner
```bash
cgminer --url stratum+tcp://192.168.1.100:3334 --user YOUR_ADDRESS --pass x
```

#### BFGMiner
```bash
bfgminer -o stratum+tcp://192.168.1.100:3334 -u YOUR_ADDRESS -p x
```

#### NiceHash Miner
```
Algorithm: SHA256
Stratum: 192.168.1.100:3334
Username: YOUR_ADDRESS
Password: x
```

---

## 📊 Monitoring & Analysis

### Real-Time Display
The proxy provides continuous monitoring output:

```
⛏️  ULTRA-FAST MINING PROXY - COMPREHENSIVE MONITOR
================================================================================
📊 PERFORMANCE: 2h 15m 30s | Active: 3 | Msg/s: 12.5 | Shares/min: 8.2
📈 SHARES: 1,247 submitted | Accept: 1,189 (95.3%) | Reject: 58 (4.7%) | Blocks: 0
💎 DIFFICULTY: Total submitted: 15,623,441
🕐 TIMING: Avg job age: 2.1s | Future jobs: 0 | Stale jobs: 0 | Anomalies: 0
🌐 NTP: Last sync 15m ago | Offset: 12.3ms
⛏️  MINERS: 3 active
🌊 POOL STATS: Total hashrate: 487GH/s | Workers: 3 | Best share: 125,034
   192.168.1.101: 423 shares | 187.5/hr | 96.2% accept | Best: 89,234 | Rate: 201.3GH/s
   192.168.1.102: 301 shares | 133.8/hr | 94.8% accept | Best: 125,034 | Rate: 156.7GH/s
   192.168.1.103: 523 shares | 232.4/hr | 95.9% accept | Best: 67,891 | Rate: 128.9GH/s
✅ SECURITY: All systems normal - no suspicious activity
```

### Log Files Generated

#### `ultra_proxy.log`
General operational logs

#### `suspicious_activity.txt`
Detailed fraud detection alerts:
```
[2024-01-15T14:23:45.123Z] HIGH: timing_attacks
Description: Extreme timestamp anomaly: Job timestamp off by 2.3 hours
Data: {
  "job_id": "6a4d2f1e",
  "timestamp_difference": 8280.5,
  "miner": "192.168.1.101"
}
```

#### `geek_mode_analysis.txt`
Technical deep-dive logs for advanced users

#### `share_analysis.txt`
CSV format share tracking:
```csv
timestamp,miner_addr,worker,job_id,nonce,share_difficulty,job_age_seconds,is_block,msg_id
2024-01-15T14:23:45.123Z,192.168.1.101,worker1,6a4d2f1e,a1b2c3d4,1024.5,2.1,false,12
```

#### `timing_analysis.txt`
Detailed timing forensics data

### Pool Stats Integration
When configured with your mining address, the proxy fetches:
- Real-time hashrate from pool
- Worker-specific statistics
- Historical performance data
- Best share achievements

---

## ⚙️ Advanced Configuration

### NTP Servers
Customize time synchronization sources:
```python
NTP_SERVERS = ['pool.ntp.org', 'time.google.com', 'time.cloudflare.com']
```

### Performance Tuning
```python
BUFFER_SIZE = 16384        # Network buffer size
SOCKET_TIMEOUT = 0.1       # Socket timeout for responsiveness
```

### Detection Sensitivity
```python
# Timing thresholds
MAX_TIMESTAMP_DRIFT = 7200    # 2 hours
STALE_JOB_THRESHOLD = 300     # 5 minutes
RAPID_SHARE_THRESHOLD = 0.005 # 5 milliseconds

# Extranonce analysis
MIN_EXTRANONCE2_SIZE = 4      # Minimum adequate nonce space
```

---

## 🚨 Alert Types & Responses

### High Severity Alerts
- **Extranonce Manipulation**: Pool-assigned nonce changes
- **Extreme Timing Anomalies**: Jobs with timestamps hours off
- **Rapid Share Submission**: Shares submitted within milliseconds

### Medium Severity Alerts  
- **Future Timestamps**: Jobs timestamped in the future
- **Stale Jobs**: Very old job submissions
- **Limited Nonce Space**: Inadequate search space allocation

### Low Severity Alerts
- **Common Rejections**: Normal pool rejection reasons
- **Minor Timing Drift**: Small timestamp discrepancies

---

## 🔒 Security Features

### Fraud Detection
The proxy monitors for:
- **Share Skimming**: Redirecting successful shares
- **Job Withholding**: Hiding profitable work
- **Timing Attacks**: Manipulating timestamps
- **Nonce Space Abuse**: Exploiting search space allocation

### Protection Methods
- **Passive Monitoring**: No interference with legitimate mining
- **NTP Synchronization**: Accurate timing reference
- **Pattern Analysis**: Statistical anomaly detection
- **Forensic Logging**: Detailed evidence collection

---

## 🤝 Troubleshooting

### Common Issues

#### "ntplib not installed"
```bash
pip install ntplib
```

#### "Connection refused"
- Check pool host and port configuration
- Verify network connectivity to pool
- Ensure firewall allows outbound connections

#### "No pool stats available"
- Verify MINING_ADDRESS is correct
- Check pool API accessibility
- Some pools may not provide public APIs

#### High reject rate
- Check timing synchronization
- Verify job age in logs
- Review network latency to pool

### Performance Issues

#### High latency forwarding
- Check NTP synchronization
- Review network conditions
- Monitor CPU usage during peak mining

#### Memory usage growth
- Restart proxy periodically for long-term operation
- Monitor log file sizes
- Clear old analysis data if needed

---

## 📝 License & Disclaimer

This software is for educational and monitoring purposes. Users are responsible for:
- Complying with pool terms of service
- Ensuring legal mining operations
- Protecting their mining infrastructure

The proxy does not modify mining operations or interfere with legitimate mining activities.

---

## 🔧 Support

For technical support:
1. Check log files for detailed error information
2. Review configuration settings
3. Verify network connectivity
4. Monitor system resources

Advanced users can enable GEEK_MODE for detailed technical analysis and debugging information.
