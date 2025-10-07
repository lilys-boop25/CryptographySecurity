# Many-Time Pad Solver

This solver recovers the plaintext of the last ciphertext when the same one-time pad keystream is mistakenly reused across multiple messages.

## Approach (≤300 words)
We exploit that XORing two ciphertexts produced with the same keystream cancels the keystream and yields the XOR of the two plaintexts. When one plaintext has a space (0x20) and the other has an ASCII letter, their XOR is also an ASCII letter. Aggregating pairwise XORs across many ciphertexts provides strong evidence of positions that were spaces in various messages. From these positions, we infer keystream bytes by XORing the corresponding ciphertext bytes with 0x20.

After seeding keystream guesses with the space-heuristic, we refine the keystream without any known plaintext by choosing, for each unknown position, the key byte that yields the highest fraction of printable ASCII across all ciphertexts. We bias toward letters and spaces but do not assume any crib. This converges on a readable plaintext for the target.

Finally, we decrypt the target ciphertext with the derived keystream to obtain the secret message.

## Files
- `solve.py`: Main solver. Prints plaintext and writes `secret.txt`.
- `secret.txt`: Output containing the recovered plaintext of the last ciphertext.

## Usage
```
python3 solve.py
```
This prints the secret message and writes it to `secret.txt`.
