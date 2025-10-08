*Approach Explanation

This solution exploits the fundamental weakness of reusing a one-time pad key: when the same key encrypts multiple plaintexts, XORing two ciphertexts together cancels out the key, leaving only the XOR of the two plaintexts.

##Core Attack Strategy:

| Step | Method | Purpose |
|------|--------|---------|
| 1. XOR ciphertexts | Remove key, create `Pi ⊕ Pj` | Detect patterns between plaintexts |
| 2. Count alphabetic results | Identify probable space positions | Exploit property `space ⊕ [a-zA-Z] = [a-zA-Z]` |
| 3. Derive key from spaces | `K[pos] = C[pos] ⊕ 0x20` | Recover key bytes at space positions |

##Key Techniques:

- Space Detection: When space (0x20) XORs with alphabetic characters, it flips the case bit, producing another letter. High frequency of alphabetic XOR results indicates a space position.
- Printability Scoring: For unknown key positions, the algorithm tests all 256 candidates and assigns scores based on: printable ratio (×7.0), letter ratio (×2.2), space ratio (×0.8), common punctuation (×0.5), and penalties for rare characters (×-1.2).
- Manual Hints: Supports human intervention through MANUAL_HINTS list, allowing strategic key recovery when automated methods fall short.

The approach successfully recovers the target plaintext without the original key, demonstrating why key reuse catastrophically breaks stream cipher security.
