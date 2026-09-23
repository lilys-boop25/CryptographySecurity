# Programming Assignment 1: Many Time Pad

The ciphertexts were encrypted with the same one-time-pad / stream-cipher key, so
XORing two ciphertexts cancels the key:

`C1 xor C2 = P1 xor P2`

This leaks information about the plaintexts. In ASCII, a space (`0x20`) XORed
with an alphabetic character flips its case and still looks alphabetic. Therefore,
when many ciphertext pairs produce alphabetic XOR bytes at the same position, it
is likely that one of the two plaintexts contains a space there. From that guess,
the key byte is recovered as:

`key_byte = ciphertext_byte xor ord(" ")`

The solver scores each possible key byte by checking whether the resulting
characters across all ciphertexts look like English text, and gives extra weight
to the space-XOR evidence. After the automatic pass, a few short cribs from
the partially readable plaintexts (for example, "We can factor" and "quantum
computers") resolve the remaining ambiguous bytes.

The recovered target plaintext is stored in `secret.txt`.
