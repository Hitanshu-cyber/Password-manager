# 🛡️ BREACH DETECTION & DATASET GUIDE
## Comprehensive Resources for Password Safety & AI Training

---

## 📊 DATASETS & DATABASES OVERVIEW

### 1. **Have I Been Pwned (HIBP) - RECOMMENDED ⭐**

**What it is:**
- 847+ million compromised passwords (as of 2025)
- Updated regularly with new breaches
- Industry-standard for breach checking
- Used by 1Password, Bitwarden, Microsoft, etc.

**Download Options:**

#### Option A: Full Database Download (SHA-1 Hashes)
```bash
# Size: ~35GB (compressed ~11GB)
# Contains: 847M+ password hashes

# Using official downloader (requires .NET)
dotnet tool install --global haveibeenpwned-downloader
haveibeenpwned-downloader

# Alternative: Using curl with parallel downloads
for i in {00000..FFFFF}; do
  curl -s "https://api.pwnedpasswords.com/range/$i" >> hibp_hashes.txt
done
```

#### Option B: Bloom Filter (Recommended for Offline Use)
```bash
# Project: easypwned
# Size: ~1GB (bloom filter)
# Speed: Extremely fast lookups

docker pull easybill/easypwned:latest

# Or download pre-built bloom filter
wget https://github.com/easybill/easypwned/releases/download/v0.0.26/pwned_passwords.bloom
```

**Integration into Your Project:**

```java
// Add to dependencies in pom.xml
<dependency>
    <groupId>com.google.guava</groupId>
    <artifactId>guava</artifactId>
    <version>32.1.3-jre</version>
</dependency>

// BreachChecker.java
import com.google.common.hash.BloomFilter;
import com.google.common.hash.Funnels;
import java.nio.charset.Charset;

public class BreachChecker {
    private BloomFilter<String> bloomFilter;
    private static final int EXPECTED_INSERTIONS = 850_000_000;
    private static final double FALSE_POSITIVE_PROBABILITY = 0.01;
    
    public BreachChecker() {
        // Load bloom filter from disk
        bloomFilter = BloomFilter.create(
            Funnels.stringFunnel(Charset.defaultCharset()),
            EXPECTED_INSERTIONS,
            FALSE_POSITIVE_PROBABILITY
        );
        loadBreachData();
    }
    
    public boolean isBreached(String password) {
        // Hash password with SHA-1
        String hash = sha1(password);
        return bloomFilter.mightContain(hash);
    }
    
    private String sha1(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] hash = md.digest(input.getBytes("UTF-8"));
            return bytesToHex(hash);
        } catch (Exception e) {
            return "";
        }
    }
}
```

**HIBP API (Online - Requires Internet):**
```bash
# k-Anonymity API (privacy-preserving)
# Only sends first 5 chars of hash

curl https://api.pwnedpasswords.com/range/21BD1

# Returns:
# 00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2  (suffix:count)
# 011053FD0102E94D6AE2F8B83D76FAF94F6:1
# ...
```

---

### 2. **RockYou Password Lists**

**What it is:**
- 14.3 million passwords from 2009 RockYou breach
- Most commonly used for penetration testing
- Available in multiple variations

**Download Locations:**

```bash
# Original RockYou (14.3M passwords)
wget https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz
tar -xzf rockyou.txt.tar.gz

# RockYou2024 (10 billion passwords - HUGE!)
# Available on Kaggle: https://www.kaggle.com/datasets/bwandowando/common-password-list-rockyou2024-txt

# SecLists variations (curated subsets)
git clone https://github.com/danielmiessler/SecLists.git
cd SecLists/Passwords/Leaked-Databases/

# Files available:
# - rockyou-10.txt (top 10 passwords)
# - rockyou-15.txt (top 15 passwords)
# - rockyou-20.txt (top 20 passwords)
# - rockyou-75.txt (top 75 passwords)
# - rockyou.txt.tar.gz (full 14.3M)
```

**Integration:**

```java
// SimpleBreachList.java
public class SimpleBreachList {
    private Set<String> breachedPasswords;
    
    public SimpleBreachList(String filepath) {
        breachedPasswords = new HashSet<>();
        loadFromFile(filepath);
    }
    
    private void loadFromFile(String filepath) {
        try (BufferedReader br = new BufferedReader(new FileReader(filepath))) {
            String line;
            while ((line = br.readLine()) != null) {
                breachedPasswords.add(line.trim().toLowerCase());
            }
        } catch (IOException e) {
            System.err.println("Failed to load breach list: " + e.getMessage());
        }
    }
    
    public boolean isBreached(String password) {
        return breachedPasswords.contains(password.toLowerCase());
    }
    
    public int getBreachCount() {
        return breachedPasswords.size();
    }
}
```

---

### 3. **Password Strength Training Datasets**

**For AI/ML Model Training:**

#### Dataset A: PWLDS (10M+ labeled passwords)
```bash
# Source: https://github.com/Infinitode/PWLDS
# Format: CSV with columns [Password, Strength_Level]
# Strength Levels: 0 (very weak) to 4 (very strong)

git clone https://github.com/Infinitode/PWLDS.git
cd PWLDS

# Files:
# - pwlds_0.csv (strength level 0)
# - pwlds_1.csv (strength level 1)
# - pwlds_2.csv (strength level 2)
# - pwlds_3.csv (strength level 3)
# - pwlds_4.csv (strength level 4)
```

**Data Structure:**
```csv
Password,Strength_Level
password123,0
P@ssw0rd,1
MyP@ss2024,2
Tr0ub4dor&3,3
?8kF#mQ2$vL9@xZ1,4
```

#### Dataset B: Password Strength Classifier Dataset
```bash
# Source: Kaggle - 670k passwords
# Link: https://www.kaggle.com/datasets/bhavikbb/password-strength-classifier-dataset

# Columns: password, strength
# Strength: 0 (weak), 1 (medium), 2 (strong)
```

#### Dataset C: Common Credentials
```bash
# SecLists Common Credentials
cd SecLists/Passwords/Common-Credentials/

# Files:
# - 10-million-password-list-top-1000000.txt
# - 10-million-password-list-top-10000.txt
# - 10-million-password-list-top-100000.txt
# - xato-net-10-million-passwords.txt (5.2M unique)
```

---

## 🤖 AI MODEL TRAINING APPROACHES

### Approach 1: Fine-tune TinyLlama on Password Dataset

**Why Fine-tune?**
- Better pattern recognition than rule-based
- Context-aware suggestions
- Learns from real breach data

**Steps:**

1. **Prepare Training Data**

```python
# prepare_dataset.py
import pandas as pd
from datasets import Dataset

# Load PWLDS dataset
df = pd.read_csv('pwlds_full.csv')

# Create prompt-response pairs
def create_prompts(row):
    password = row['Password']
    strength = row['Strength_Level']
    
    # Mask actual password for privacy
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    prompt = f"""Analyze this password pattern:
Length: {length}
Uppercase: {has_upper}
Digits: {has_digit}
Special chars: {has_special}

Provide strength score (0-4) and suggestion."""

    response = f"""STRENGTH: {strength}
ANALYSIS: {get_analysis(strength)}
SUGGESTION: {get_suggestion(strength, length, has_upper, has_digit, has_special)}"""
    
    return {'prompt': prompt, 'response': response}

# Apply to dataset
dataset = Dataset.from_pandas(df.apply(create_prompts, axis=1))
dataset.save_to_disk('./password_training_data')
```

2. **Fine-tune with QLoRA (Efficient)**

```python
# finetune_tinyllama.py
from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer

# Load TinyLlama
model = AutoModelForCausalLM.from_pretrained(
    "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
    load_in_4bit=True,
    device_map="auto"
)

tokenizer = AutoTokenizer.from_pretrained("TinyLlama/TinyLlama-1.1B-Chat-v1.0")

# LoRA config
peft_config = LoraConfig(
    r=16,
    lora_alpha=32,
    target_modules=["q_proj", "v_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM"
)

model = prepare_model_for_kbit_training(model)
model = get_peft_model(model, peft_config)

# Training
trainer = SFTTrainer(
    model=model,
    train_dataset=dataset,
    max_seq_length=512,
    args=TrainingArguments(
        output_dir="./tinyllama-password-expert",
        num_train_epochs=3,
        per_device_train_batch_size=4,
        learning_rate=2e-4,
        logging_steps=10,
        save_steps=100
    )
)

trainer.train()
model.save_pretrained("./tinyllama-password-expert-final")
```

3. **Export to ONNX for Java**

```python
# export_onnx.py
from optimum.onnxruntime import ORTModelForCausalLM

# Load fine-tuned model
model = ORTModelForCausalLM.from_pretrained(
    "./tinyllama-password-expert-final",
    export=True
)

# Save ONNX model
model.save_pretrained("./models/tinyllama-password-onnx")
```

---

### Approach 2: Train Lightweight ML Model (Faster, Simpler)

**For Less Resource-Intensive Deployment:**

```python
# train_ml_model.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib

# Load dataset
df = pd.read_csv('pwlds_full.csv')

# Feature engineering
def extract_features(password):
    return {
        'length': len(password),
        'uppercase_count': sum(1 for c in password if c.isupper()),
        'lowercase_count': sum(1 for c in password if c.islower()),
        'digit_count': sum(1 for c in password if c.isdigit()),
        'special_count': sum(1 for c in password if not c.isalnum()),
        'has_uppercase': any(c.isupper() for c in password),
        'has_lowercase': any(c.islower() for c in password),
        'has_digit': any(c.isdigit() for c in password),
        'has_special': any(not c.isalnum() for c in password),
        'entropy': calculate_entropy(password)
    }

X = pd.DataFrame([extract_features(p) for p in df['Password']])
y = df['Strength_Level']

# Train
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
print(f"Accuracy: {model.score(X_test, y_test):.2%}")

# Save for Java
joblib.dump(model, 'password_strength_model.pkl')
```

---

## 🔧 IMPLEMENTATION STRATEGIES

### Strategy 1: Multi-Tiered Breach Checking (RECOMMENDED)

```java
public class MultiTierBreachChecker {
    private SimpleBreachList commonPasswords;  // Top 100K
    private BloomFilter<String> hibpBloom;      // 847M HIBP
    private AIPasswordAnalyzer aiAnalyzer;      // ML model
    
    public BreachCheckResult checkPassword(String password) {
        BreachCheckResult result = new BreachCheckResult();
        
        // Tier 1: Quick common password check (instant)
        if (commonPasswords.isBreached(password)) {
            result.setBreached(true);
            result.setSeverity("CRITICAL");
            result.setMessage("This is one of the most common passwords!");
            return result;
        }
        
        // Tier 2: Bloom filter check (very fast)
        if (hibpBloom != null && hibpBloom.mightContain(sha1(password))) {
            result.setBreached(true);
            result.setSeverity("HIGH");
            result.setMessage("Found in known breach database");
            return result;
        }
        
        // Tier 3: AI pattern analysis (slower but thorough)
        if (aiAnalyzer != null) {
            AIPasswordAnalyzer.AnalysisResult aiResult = 
                aiAnalyzer.analyzePassword(password);
            
            if (aiResult.score < 5) {
                result.setBreached(false);
                result.setSeverity("MEDIUM");
                result.setMessage("Weak pattern detected: " + aiResult.weakness);
                result.setSuggestion(aiResult.suggestion);
            }
        }
        
        return result;
    }
}
```

---

### Strategy 2: Offline Database with SQLite

**Create Breach Database:**

```bash
# Convert HIBP hashes to SQLite
# breach_import.py

import sqlite3
import hashlib

conn = sqlite3.connect('breach_database.db')
cursor = conn.cursor()

# Create table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS breached_hashes (
        hash_prefix TEXT,
        hash_suffix TEXT,
        count INTEGER,
        PRIMARY KEY (hash_prefix, hash_suffix)
    )
''')

cursor.execute('CREATE INDEX IF NOT EXISTS idx_prefix ON breached_hashes(hash_prefix)')

# Import HIBP data
with open('hibp_hashes.txt', 'r') as f:
    for line in f:
        parts = line.strip().split(':')
        if len(parts) == 2:
            full_hash, count = parts
            prefix = full_hash[:5]
            suffix = full_hash[5:]
            
            cursor.execute(
                'INSERT OR REPLACE INTO breached_hashes VALUES (?, ?, ?)',
                (prefix, suffix, int(count))
            )

conn.commit()
conn.close()
```

**Query in Java:**

```java
public class BreachDatabase {
    private Connection conn;
    
    public BreachDatabase(String dbPath) throws SQLException {
        conn = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
    }
    
    public boolean isBreached(String password) {
        try {
            String hash = sha1(password).toUpperCase();
            String prefix = hash.substring(0, 5);
            String suffix = hash.substring(5);
            
            String sql = "SELECT count FROM breached_hashes WHERE hash_prefix = ? AND hash_suffix = ?";
            PreparedStatement pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, prefix);
            pstmt.setString(2, suffix);
            
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                int count = rs.getInt("count");
                return count > 0;
            }
            
            return false;
        } catch (SQLException e) {
            return false;
        }
    }
}
```

---

## 📦 PROJECT INTEGRATION PLAN

### Phase 1: Basic Breach Checking (Week 1)

**Files to Add:**
```
src/main/java/com/passwordmanager/
├── BreachChecker.java
├── SimpleBreachList.java
└── BreachCheckResult.java

resources/
└── data/
    ├── top-100k-passwords.txt (SecLists)
    └── common-patterns.txt (custom)
```

**Implementation:**

```java
// Update AIPasswordAnalyzer.java
public class AIPasswordAnalyzer {
    private BreachChecker breachChecker;
    
    public AIPasswordAnalyzer() {
        // Load common password list
        String commonListPath = "resources/data/top-100k-passwords.txt";
        this.breachChecker = new SimpleBreachList(commonListPath);
    }
    
    @Override
    public boolean checkBreach(String password) {
        return breachChecker.isBreached(password);
    }
}
```

---

### Phase 2: HIBP Bloom Filter (Week 2)

**Download and Setup:**

```bash
# Download bloom filter (~1GB)
wget https://github.com/easybill/easypwned/releases/download/v0.0.26/pwned_passwords.bloom

# Place in project
mkdir -p resources/data
mv pwned_passwords.bloom resources/data/
```

**Add to pom.xml:**
```xml
<dependency>
    <groupId>com.google.guava</groupId>
    <artifactId>guava</artifactId>
    <version>32.1.3-jre</version>
</dependency>
```

---

### Phase 3: AI Model Fine-tuning (Week 3-4)

**Option A: Use Pre-trained Model**
- Download PWLDS dataset
- Fine-tune TinyLlama
- Export to ONNX
- Integrate into AIPasswordAnalyzer

**Option B: Train Lightweight ML Model**
- Train Random Forest on PWLDS
- Export as .pkl or .pmml
- Load in Java using JPMML or similar

---

## 🛡️ SECURITY IMPROVEMENTS CHECKLIST

### Level 1: Basic (Implement First)
- [ ] Add top 100K common passwords check
- [ ] Implement pattern detection (sequential, repeating)
- [ ] Add minimum entropy calculation
- [ ] Warn on dictionary words

### Level 2: Intermediate (Week 2)
- [ ] Integrate HIBP bloom filter
- [ ] Add zxcvbn-style analysis
- [ ] Implement password expiry tracking
- [ ] Add 2FA recommendation

### Level 3: Advanced (Week 3-4)
- [ ] Fine-tune AI model on breach data
- [ ] Implement similarity detection (Levenshtein distance)
- [ ] Add password generation based on entropy
- [ ] Context-aware suggestions (domain-specific)

### Level 4: Enterprise (Future)
- [ ] Real-time breach monitoring (optional online check)
- [ ] Password policy enforcement
- [ ] Compliance reporting (NIST, PCI-DSS)
- [ ] Multi-language support

---

## 📊 DATASET COMPARISON

| Dataset | Size | Format | Use Case | License |
|---------|------|--------|----------|---------|
| **HIBP Full** | 35GB (11GB compressed) | SHA-1 hashes | Production breach checking | CC BY 4.0 |
| **HIBP Bloom** | 1GB | Bloom filter | Fast offline checking | Open |
| **RockYou** | 133MB | Plaintext | Testing, training | Public domain |
| **RockYou2024** | 90GB+ | Plaintext | Comprehensive training | Check license |
| **PWLDS** | 500MB | CSV (labeled) | ML model training | CC BY 4.0 |
| **SecLists** | Various | Text files | Multiple purposes | MIT |

---

## 🚀 QUICK START IMPLEMENTATION

**Minimum Viable Breach Detection (30 minutes):**

1. **Download dataset:**
```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt
```

2. **Add to project:**
```bash
mkdir -p src/main/resources/data
mv 10-million-password-list-top-100000.txt src/main/resources/data/
```

3. **Update AIPasswordAnalyzer.java:**
```java
// Add at initialization
private Set<String> commonPasswords = new HashSet<>();

private void loadCommonPasswords() {
    try (InputStream is = getClass().getResourceAsStream("/data/10-million-password-list-top-100000.txt");
         BufferedReader br = new BufferedReader(new InputStreamReader(is))) {
        
        String line;
        while ((line = br.readLine()) != null) {
            commonPasswords.add(line.trim().toLowerCase());
        }
    } catch (IOException e) {
        System.err.println("[AI] Failed to load common passwords");
    }
}

@Override
public boolean checkBreach(String password) {
    return commonPasswords.contains(password.toLowerCase());
}
```

4. **Test:**
```java
AIPasswordAnalyzer ai = new AIPasswordAnalyzer();
System.out.println(ai.checkBreach("password123")); // true
System.out.println(ai.checkBreach("MyUn1qu3P@ssw0rd!")); // false
```

---

## 📚 ADDITIONAL RESOURCES

### Tools & Libraries

**Java:**
- [zxcvbn4j](https://github.com/nulab/zxcvbn4j) - Dropbox's password strength estimator for Java
- [Passay](https://www.passay.org/) - Password policy enforcement library
- [JPMML](https://github.com/jpmml) - ML model execution in Java

**Python (for training):**
- [zxcvbn](https://github.com/dropbox/zxcvbn) - Original password strength estimator
- [PassGAN](https://github.com/brannondorsey/PassGAN) - GAN for password generation/analysis
- [Hugging Face Transformers](https://huggingface.co/) - For LLM fine-tuning

### Research Papers

1. "Testing Metrics for Password Creation Policies" (NIST)
2. "The Tangled Web of Password Reuse" (CMU)
3. "Fast, Lean, and Accurate: Modeling Password Guessability Using Neural Networks" (USENIX)

---

## ⚖️ LEGAL & ETHICAL CONSIDERATIONS

### DO:
✅ Use breach data to **protect** users  
✅ Inform users if their password is compromised  
✅ Provide alternatives and education  
✅ Attribute datasets properly (licenses)  

### DON'T:
❌ Store plaintext passwords (even for analysis)  
❌ Share users' actual passwords externally  
❌ Use breach data for malicious purposes  
❌ Violate dataset licenses  

### Privacy by Design:
- Hash passwords before checking (k-anonymity)
- Never send plaintext to external services
- Local-only processing (offline mode)
- Transparent to users about checks performed

---

## 🎯 RECOMMENDED IMPLEMENTATION PATH

**For Your Project:**

### Immediate (This Week):
1. Download SecLists top 100K passwords
2. Integrate into AIPasswordAnalyzer
3. Add breach warning to UI
4. Update password analysis flow

### Short-term (Next 2 Weeks):
1. Download HIBP bloom filter (1GB)
2. Integrate Guava BloomFilter
3. Add multi-tier checking
4. Implement SQLite breach cache

### Medium-term (Next Month):
1. Download PWLDS training dataset
2. Fine-tune TinyLlama OR train Random Forest
3. Export model to ONNX/PMML
4. Integrate into AIPasswordAnalyzer

### Long-term (Future):
1. Implement pattern-based detection
2. Add similarity analysis
3. Create custom training pipeline
4. Build automated model updates

---

## 💡 CONCLUSION

**Your next steps:**

1. **Start simple**: Integrate top 100K common passwords list
2. **Add bloom filter**: Download HIBP bloom filter for comprehensive checking
3. **Train AI**: Use PWLDS dataset to fine-tune TinyLlama
4. **Iterate**: Improve based on user feedback

**Expected Impact:**
- 🛡️ Block 90%+ of weak passwords
- 🚀 Catch breached passwords instantly
- 🤖 Provide intelligent suggestions
- 📈 Increase overall security posture

All datasets mentioned are freely available and legal to use for security purposes. Always respect licenses and user privacy!

---

**Need help implementing? Let me know which approach you want to take first!** 🚀
