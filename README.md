# Cisco-Grade Password Manager with AI Defense

A production-ready password management system featuring hardware-backed security, AI-driven threat detection, and zero-knowledge sync architecture.

## 🔒 Security Features

- **AES-256-GCM Encryption**: Authenticated encryption with integrity verification
- **Simulated HSM**: Hardware isolation for master keys
- **AI Pattern Analysis**: Markov Chain-based predictability detection
- **Bloom Filter Breach Shield**: Offline breach checking with minimal memory
- **Adaptive MFA**: TOTP-based multi-factor authentication
- **Zero-Knowledge Sync**: HMAC-verified tamper-evident backups
- **Autonomous Defense**: Thread anomaly detection and auto-lockdown

## 🤖 AI Components

1. **Markov Chain Model**: Analyzes character transition probabilities to reject predictable passwords
2. **Bloom Filter**: Probabilistic data structure for efficient breach detection (< 2MB for 100K+ passwords)
3. **Risk Manager**: Rule-based expert system for real-time threat scoring

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────┐
│  Main.java (Entry Point)                        │
├──────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────┐             │
│  │ RiskManager │  │ TOTPManager  │             │
│  └─────────────┘  └──────────────┘             │
├──────────────────────────────────────────────────┤
│  ┌────────────────────────────────────┐         │
│  │ AIPasswordAnalyzer                 │         │
│  │  ├─ MarkovChain                    │         │
│  │  └─ BloomFilter                    │         │
│  └────────────────────────────────────┘         │
├──────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────┐             │
│  │ SimulatedHSM│  │ SyncManager  │             │
│  └─────────────┘  └──────────────┘             │
├──────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌──────────────────┐     │
│  │ CryptoManager   │  │ DatabaseManager  │     │
│  └─────────────────┘  └──────────────────┘     │
└──────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Java 11 or higher
- SQLite JDBC Driver (`sqlite-jdbc-3.x.x.jar` in `lib/` directory)

### Installation
```bash
git clone https://github.com/yourusername/password-manager.git
cd password-manager
./run.sh
```

### First Run
1. Register Root Admin with a strong password
2. Choose "Cyber Resistance Mode" for maximum security
3. Import breach list: Admin Command → 7 → `breach_list.txt`
4. Train AI model: Admin Command → 6

## 📊 Performance Metrics

- **Concurrency**: 20 simultaneous operations (race condition tested)
- **Encryption**: AES-256-GCM with < 1ms overhead
- **Breach Lookup**: < 2ms for 100K+ password database
- **Memory**: < 50MB total footprint

## 🧪 Security Testing

Run the enterprise test suite:
```bash
javac -cp ".:lib/*" EnterpriseSecurityTest.java
java -cp ".:lib/*" EnterpriseSecurityTest
```

Tests include:
- Cryptographic integrity verification
- 20-thread race condition stress
- SQL injection fuzzing
- Buffer overflow protection
- AI breach detection validation

## 🎓 Educational Use

This project was developed as part of the Microsoft Elevate AICTE Internship program to demonstrate enterprise-grade security engineering practices.

## ⚠️ Disclaimer

This is an educational project demonstrating security concepts. For production use, consider:
- Replace `SimulatedHSM` with actual hardware security modules (YubiKey, TPM)
- Professional security audit
- Regular breach list updates
- Compliance with local data protection regulations

## 📝 License

MIT License

## 🤝 Contributing

Contributions welcome! Please open an issue first to discuss proposed changes.
