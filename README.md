 TASK-4
 Password Security &amp; Authentication Analysis
Password Security & Authentication Analysis Report
This report covers the key concepts from Task 4, including hashing fundamentals, attack methods, defenses, and practical analysis. It directly addresses the interview questions and provides actionable recommendations for pentesting and securing authentication systems. As a pentester with authorization, you can use this as a foundation for hands-on labs with Hashcat or John the Ripper on test hashes.

1. Core Concepts: Hashing vs. Encryption
What is hashing?
Hashing is a one-way cryptographic function that converts a variable-length input (e.g., a password) into a fixed-length output (hash) of seemingly random bytes. It's designed to be irreversible—you can't "unhash" it to recover the original input. Common algorithms include MD5 (128-bit, insecure), SHA-1 (160-bit, deprecated), SHA-256 (secure), and adaptive ones like bcrypt or Argon2. Hashes are used to store passwords securely: during login, the user's input is hashed and compared to the stored hash.

Difference between hashing and encryption?

Hashing: One-way (no decryption key), deterministic (same input always yields same output), collision-resistant (hard to find two inputs with the same hash). Used for integrity checks and password storage.
Encryption: Two-way (reversible with a key), can be symmetric (e.g., AES) or asymmetric (e.g., RSA). Used for confidential data transmission/storage where recovery is needed.
Key distinction: You encrypt to hide data temporarily; you hash to verify data without exposing it. Weak legacy systems sometimes encrypt passwords (reversible = bad), but modern ones always hash.

2. Password Storage and Hash Identification
Passwords should never be stored in plaintext or reversibly encrypted. Instead:

Use salted hashes: Append a unique random salt per user before hashing to prevent rainbow table attacks (precomputed hash lookups).
Prefer slow, adaptive hashes like bcrypt, scrypt, PBKDF2, or Argon2—these make brute-forcing computationally expensive.
Identifying hash types (for pentesting leaked dumps):
Use tools like hashid (Kali: hashid <hash>), online identifiers (e.g., hashes.com), or Hashcat's hashcat --example-hashes | grep <pattern>. Examples:



Hash Type	                    Example	                                                                      Cracking Difficulty
MD5	                          5f4dcc3b5aa765d61d8327deb882cf99 (password: "password")	                      Easy (fast, unsalted)
SHA-1	                        5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8	                                     Moderate
bcrypt                       	$2y$10$N9qo8uLOickgx2ZMRZoMye                               	                 Hard (iterative, salted)

Generating test hashes (for lab practice):
bash
 MD5 (insecure demo only)
echo -n "password" | md5sum
 bcrypt (secure, using htpasswd or Python)
htpasswd -bnBC 10 "" weakpass | tr -d ':'
Save these to hashes.txt for cracking.

3. Cracking Attacks: Brute Force vs. Dictionary
What is a brute force attack?
A brute force attack tries every possible combination of characters (e.g., all 8-char lowercase: 26^8 = 208 billion attempts). It's exhaustive but slow for long/strong passwords. Tools optimize with GPU acceleration (Hashcat) or ASIC rules (John).

Brute force vs. dictionary attacks:

Dictionary: Uses wordlists (e.g., rockyou.txt) + rules (mutations like "password123"). Faster for common/weak passwords.
Hybrid: Dictionary + brute-force suffixes (e.g., Hashcat's -a 6 or -a 7).
Why weak passwords fail: Predictable patterns (e.g., "Password1!", dictionary words, personal info) crack in seconds on GPUs. Unsalted/weak hashes (MD5) amplify this.
Hands-on cracking example (authorized pentest lab):
Download rockyou.txt: wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
Crack MD5 hash from above:

bash



 Hashcat (GPU-optimized)
hashcat -m 0 -a 0 hashes.txt rockyou.txt   Dictionary
hashcat -m 0 -a 3 hashes.txt ?l?l?l?l?l?l?l?l   Brute force 8 lowercase

 John the Ripper
john --wordlist=rockyou.txt hashes.txt
john --show hashes.txt   Show cracked
On a decent GPU, "password" cracks in <1s; bcrypt takes days/years.

4. Multi-Factor Authentication (MFA)
Why is MFA important?
MFA adds layers beyond passwords: something you know (password), have (TOTP app like Authy), or are (biometrics). Even if attackers crack/steal your hash or phish your password, they need the second factor. Stats: MFA blocks 99.9% of account takeover attacks (Microsoft). Weakness: SMS MFA (SIM-swappable); prefer app-based TOTP or hardware keys (YubiKey).

5. What Makes a Strong Password?
Length: 16+ characters (beats complexity rules).
Randomness: High entropy (use diceware or password managers like Bitwarden).
No patterns: Avoid dictionary words, names, repeats (e.g., "correcthorsebatterystaple" > "P@ssw0rd1").
Unique per site: Rotate via manager.
Check strength: zxcvbn library or haveibeenpwned.com/pwnedpasswords.
6. Recommendations for Strong Authentication
Enforce hashing: Mandate bcrypt/Argon2 with high work factors (cost=12+). Salt per-user.
Password policies: 12+ chars, no reuse, check against breached lists (HIBP API).
Rate limiting: Block brute-force (e.g., fail2ban, CAPTCHA after 5 tries).
MFA everywhere: TOTP/hardware default; audit bypasses.
Monitor/audit: Log failed logins, use tools like pwaudit for dumps.
Pentest checklist: Dump /etc/shadow (Linux), crack with Hashcat, test MFA bypass (e.g., race conditions).
Defenses summary:


Attack	Mitigation
Dictionary/Brute	Slow hashes + rate limits
Rainbow Tables	Per-user salts
Credential Stuffing	Unique pwds + MFA
