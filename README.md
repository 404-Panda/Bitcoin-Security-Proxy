⚡ Ultra-Fast Bitcoin Mining Proxy - Anti-Cheat Detection System
Lightning-fast Stratum proxy with comprehensive pool manipulation detection and timing forensics

⚡ Ultra-Fast Bitcoin Mining Proxy - Anti-Cheat Detection System
Lightning-fast Stratum proxy with comprehensive pool manipulation detection and timing forensics
Show Image
Show Image
Show Image
🎯 The Problem: Pool Manipulation is Real
Bitcoin mining pools hold enormous power over individual miners. With billions of dollars at stake, some pools engage in sophisticated manipulation tactics that can cost miners significant revenue. This proxy levels the playing field.
Common Pool Attack Vectors:
🕐 Timing Attacks

Delayed job delivery to specific miners
Stale job manipulation
Future-dated timestamps to invalidate shares

💎 Share Skimming

Stealing near-miss shares that should credit to miner
False rejection of valid shares
Block withholding attacks

🔢 Nonce Space Manipulation

Limiting extranonce2 space to reduce mining efficiency
Reassigning extranonce1 to fragment search space
Difficulty manipulation for specific miners

📊 Statistical Fraud

Rejection rate manipulation
Vardiff attacks to lower effective hashrate
Credit skimming through micro-manipulations

🛡️ The Solution: Transparent Monitoring
This proxy sits between your miner and the pool, providing real-time verification of every interaction. When enough miners use monitoring tools like this, pools can't get away with manipulation.
Key Principle: Trust, but verify everything.
⚡ Features
🚀 Ultra-Low Latency Design

TCP_NODELAY optimization for instant packet forwarding
Microsecond-level performance monitoring
16KB buffers for maximum throughput
Threaded architecture - each connection is independent
Zero mining interruption - transparent operation

🕐 Advanced Timing Forensics

NTP synchronization with multiple time servers
Job timestamp verification against accurate time
Share submission timing analysis
Stale job detection (>30 minutes old)
Future job alerts (>10 minutes ahead)
ntime manipulation detection

🔍 Comprehensive Share Analysis

Real-time difficulty calculation for every share
Near-miss detection (shares within 5% of target)
Block detection with forensic proof
Acceptance/rejection rate monitoring
Share interval pattern analysis
CSV logging for statistical analysis

🧬 Extranonce Forensics

Nonce space allocation analysis
Pool vs miner controlled space breakdown
Extranonce1 change detection (major red flag)
Search space quality assessment
Mining efficiency impact analysis

📊 Pool Behavior Monitoring

Response time tracking
Rejection pattern analysis
Job delivery timing
Difficulty consistency monitoring
Statistical anomaly detection

🔧 Installation
Prerequisites
bash# Python 3.8+ required
python3 --version

# Install required packages
pip install ntplib
Quick Start
bash# Clone the repository
git clone https://github.com/404-Panda/Bitcoin-Security-Proxy
cd bitcoin-mining-proxy

# Run the proxy
python3 proxy.py

# Point your miner to the proxy
# Original: miner -> pool.com:3333
# With proxy: miner -> localhost:3334 -> pool.com:3333
Configuration
Edit the configuration section in proxy.py:
pythonLISTEN_PORT = 3334          # Port for miners to connect to
POOL_HOST = 'solo.ckpool.org'  # Target pool
POOL_PORT = 3333            # Pool port
GEEK_MODE = True            # Detailed technical output
TIMING_ANALYSIS = True      # Enable timing forensics
NTP_VERIFICATION = True     # Use NTP for accurate timing
📈 Monitoring Output
Real-Time Share Tracking
📤 SHARE from 192.168.1.100:50140 | Worker: bc1q...Satoshi | Job: 6890434e... | Nonce: b0a001b2 | Difficulty: 2048.5
Geek Mode Analysis
[GEEK] [18:26:19.167] CRYPTO: Nonce space analysis for 192.168.1.100:50140
       pool_assigned_extranonce1: ab71866e
       extranonce1_bytes: 4
       miner_controlled_extranonce2_bytes: 8
       miner_controlled_nonce_bytes: 4
       total_miner_controlled_bytes: 12
       miner_search_space: 2^96
       extranonce2_quality: generous

[GEEK] [18:26:19.168] SHARE: Share submission analysis
       worker: bc1qtesc50ye5euqtr67sdqke8xdwef6klasc5vx59.Satoshi
       share_difficulty: 1024.50
       job_age_seconds: 2.1
       ntime: 68c9a6b5
       extranonce2: 000000000000001a
       coinbase_size_bytes: 201
       header_hash: 00000a7b2f8c3d9e...
       submission_interval: 45.2s
Performance Monitor
===============================================================================
⛏️  ULTRA-FAST MINING PROXY - COMPREHENSIVE MONITOR
===============================================================================
📊 PERFORMANCE: 2h 15m 30s | Active: 3 | Msg/s: 2.1 | Shares/min: 12.5
📈 SHARES: 1,247 submitted | Accept: 98.4% | Reject: 1.6% | Blocks: 2 | Near-misses: 15
🕐 TIMING: Avg job age: 1.2s | Future jobs: 0 | Stale jobs: 0 | Anomalies: 0
🌐 NTP: Last sync 23m ago | Offset: 12.3ms
⛏️  MINERS: 3 active
   192.168.1.100:50140: 847 shares | 37.6/hr | 98.8% accept | Worker: bc1q...Satoshi
   192.168.1.101:50141: 284 shares | 12.6/hr | 97.9% accept | Worker: bc1q...Alice
   192.168.1.102:50142: 116 shares | 5.1/hr | 99.1% accept | Worker: bc1q...Bob
✅ SECURITY: All systems normal - no suspicious activity
===============================================================================
Fraud Detection Alerts
🚨 SUSPICIOUS: EXTRANONCE_MANIPULATION
   Pool changed extranonce1 for 192.168.1.100:50140
   old_extranonce1: ab71866e
   new_extranonce1: cd92a771

🚨 SUSPICIOUS: TIMING_ATTACKS  
   Delayed job delivery to 192.168.1.100:50140
   interval: 45.20s
   average_interval: 12.40s

🚨 SUSPICIOUS: REJECTION_MANIPULATION
   High rejection rate for 192.168.1.100:50140
   rejection_rate: 18.5%
   total_submits: 156
   total_rejects: 29
📂 Generated Files
share_analysis.txt
CSV format with complete share data:
timestamp,miner_addr,worker,job_id,nonce,share_difficulty,job_age_seconds,is_block
2024-01-15T18:26:19.167Z,192.168.1.100:50140,bc1q...Satoshi,6890434e00020322,b0a001b2,1024.50,2.1,false
suspicious_activity.txt
Detailed fraud detection logs:
[2024-01-15T18:26:19.167Z] HIGH - EXTRANONCE_MANIPULATION
Description: Pool changed extranonce1 for 192.168.1.100:50140
Data: {
  "old_extranonce1": "ab71866e",
  "new_extranonce1": "cd92a771",
  "time_since_connect": 3847.2
}
Cryptographic Verification
Block Header Reconstruction:
Version (4 bytes) + PrevHash (32 bytes) + MerkleRoot (32 bytes) + 
Timestamp (4 bytes) + Bits (4 bytes) + Nonce (4 bytes) = 80 bytes
MerkleRoot = merkle_tree_root(coinbase_hash, merkle_branches)
Coinbase = coinbase1 + extranonce1 + extranonce2 + coinbase2
Share Difficulty Calculation:
pythondef calculate_share_difficulty(hash_hex, target):
    hash_int = int(hash_hex, 16)
    max_target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    return max_target / max(hash_int, 1)
Timing Analysis Algorithms
NTP Synchronization:
pythondef sync_ntp_time():
    for ntp_server in ['pool.ntp.org', 'time.google.com', 'time.cloudflare.com']:
        ntp_time = ntp_client.request(ntp_server).tx_time
        ntp_offset = ntp_time - local_time
Job Age Analysis:
pythondef analyze_job_timing(job_data, receive_time):
    job_timestamp = int(job_data['ntime'], 16)
    accurate_time = get_accurate_time()  # Local time + NTP offset
    timestamp_diff = job_timestamp - accurate_time
    
    # Flag suspicious timing
    if abs(timestamp_diff) > 7200:  # >2 hours
        alert_suspicious_timing()
Performance Optimizations
Zero-Copy Forwarding:
pythondef lightning_forward(src, dst, direction, addr):
    # TCP_NODELAY for instant transmission
    src.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    
    # Large buffers for efficiency
    data = src.recv(16384)
    
    # Minimal processing in critical path
    dst.sendall(data)
Microsecond Performance Tracking:
pythonstart_time = time.perf_counter()
# ... processing ...
processing_time_us = (time.perf_counter() - start_time) * 1000000
🌐 The Network Effect
Individual miners get protection. When many miners use monitoring proxies:

Pools can't target individuals - Mass monitoring makes selective attacks obvious
Statistical analysis becomes powerful - Aggregate data reveals systematic manipulation
Market pressure increases - Transparent pools gain competitive advantage
Industry standards improve - Public monitoring creates accountability

Goal: Make pool manipulation unprofitable through transparency.

🚨 Known Attack Vectors
1. Timing Attacks
Description: Pool delays job delivery to reduce effective hashrate
Detection: Job interval analysis, NTP timestamp verification
Evidence: Consistent delays exceeding network latency

3. Share Skimming
Description: Pool claims near-miss shares or rejects valid shares
Detection: Local hash verification, rejection rate analysis
Evidence: Mathematically valid shares being rejected

5. Extranonce Manipulation
Description: Pool limits nonce space or changes extranonce1 mid-session
Detection: Nonce space analysis, extranonce1 change monitoring
Evidence: Insufficient search space or mid-session changes

7. Block Withholding
Description: Pool doesn't submit blocks found by specific miners
Detection: Block detection with independent verification
Evidence: Valid blocks not appearing on blockchain

9. Vardiff Attacks
Description: Pool manipulates variable difficulty to reduce effective payouts
Detection: Difficulty trend analysis, timing correlation
Evidence: Artificial difficulty spikes correlated with miner performance

📊 Statistical Analysis
Rejection Rate Baselines
Normal: <2% rejection rate
Suspicious: 5-10% rejection rate
Fraudulent: >10% rejection rate

Timing Baselines

Normal job age: 0-30 seconds
Stale jobs: >300 seconds (suspicious)
Future jobs: >600 seconds (highly suspicious)

Nonce Space Standards

Generous: 8+ bytes extranonce2
Adequate: 4-6 bytes extranonce2
Limited: <4 bytes extranonce2 (potential manipulation)

Reporting Issues

Include proxy logs (geek_mode_analysis.txt)
Provide pool information (if safe to disclose)
Include network/timing context
Share statistical evidence

⚖️ Legal & Ethical Considerations
This software is for transparency and verification purposes only.

✅ Legal: Monitoring your own mining connections
✅ Ethical: Ensuring fair treatment by pools
✅ Beneficial: Improving industry standards through transparency
❌ Illegal: Using this to attack or compromise pool infrastructure
❌ Unethical: False accusations without evidence

Use responsibly. Verify claims with evidence. Support honest pools.
📜 License
MIT License - See LICENSE for details.
🙏 Acknowledgments

No one.. Because no one ever helps anyone.  Your on your own.. Deal with it.
