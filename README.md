# Many-Time Pad Solver (No-Crib Heuristic)

This solver recovers the plaintext of the last ciphertext when the same one-time pad keystream is mistakenly reused across multiple messages.

## Approach (≤300 words)
We exploit that XORing two ciphertexts produced with the same keystream cancels the keystream and yields the XOR of the two plaintexts. When one plaintext contains a space (0x20) and the other an ASCII letter, the XOR is typically alphabetic. Counting these events across all pairs gives “space evidence” per position for each ciphertext. Where evidence is strong, we infer the keystream byte as C ⊕ 0x20.

For positions with unknown keystream, we avoid any crib and instead search over all 256 key byte candidates and score them by how well the resulting plaintext bytes look like English across all ciphertexts. The score emphasizes printable ASCII, letters, spaces, and common punctuation, penalizes rare punctuation, and incorporates the space-evidence as a soft prior. We iterate this refinement a few passes until convergence. This produces high-quality plaintexts for ciphertexts #1–#10 and the target.

Finally, we decrypt all ciphertexts with the derived keystream and print them; the target plaintext is also saved to `secret.txt`.

## Files
- `solve.py`: Main solver. Prints plaintext and writes `secret.txt`.
- `secret.txt`: Output containing the recovered plaintext of the last ciphertext.

## Usage
```
python3 solve.py
```
This prints the secret message and writes it to `secret.txt`.
