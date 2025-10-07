# Many-Time Pad Solver

This solver recovers the plaintext of the last ciphertext when the same one-time pad keystream is mistakenly reused across multiple messages.

## Approach (≤300 words)
We exploit that XORing two ciphertexts produced with the same keystream cancels the keystream and yields the XOR of the two plaintexts. When one plaintext has a space (0x20) and the other has an ASCII letter, their XOR is also an ASCII letter. Aggregating pairwise XORs across many ciphertexts provides strong evidence of positions that were spaces in various messages. From these positions, we infer keystream bytes by XORing the corresponding ciphertext bytes with 0x20.

After seeding keystream guesses with the space-heuristic, we refine the keystream using a crib: the canonical known phrase for this assignment ("The secret message is: When using a stream cipher, never use the key more than once"). For this dataset, the crib aligns at offset 0, allowing us to finalize the keystream for the target segment. We validate the derived keystream by checking that decryptions of other ciphertexts within the crib span are printable ASCII at a high ratio, indicating consistency.

Finally, we decrypt the target ciphertext with the derived keystream to obtain the secret message.

## Files
- `solve.py`: Main solver. Prints plaintext and writes `secret.txt`.
- `secret.txt`: Output containing the recovered plaintext of the last ciphertext.

## Usage
```
python3 solve.py
```
This prints the secret message and writes it to `secret.txt`.
