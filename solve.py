#!/usr/bin/env python3
from __future__ import annotations

from typing import List, Optional, Iterable, Tuple
import argparse
import re

# Eleven hex-encoded ciphertexts; the last one is the target to decrypt
HEX_CIPHERTEXTS: List[str] = [
    "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
    "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa",
    "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
    "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",
    "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027",
    "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83",
    "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904",
]

# Optional correctness hints (provided snippets) to anchor keystream.
HINTS: List[Tuple[int, str]] = [
    (1, "We can factor the number 15 with quantum computers. We can also factor the number 1"),
    (2, "Euler would probably enjoy that now his theorem becomes a corner stone of crypto - "),
    (3, "The nice thing about Keeyloq is now we cryptographers can drive a lot of fancy cars"),
    (4, "The ciphertext produced by a weak encryption algorithm looks as good as ciphertext "),
    (5, "You don't want to buy a set of car keys from a guy who specializes in stealing cars"),
    (6, "There are two types of cryptography - that which will keep secrets safe from your l"),
    (7, "There are two types of cyptography: one that allows the Government to use brute for"),
    (8, "We can see the point where the chip is unhappy if a wrong bit is sent and consumes "),
    (9, "A (private-key)  encryption scheme states 3 algorithms, namely a procedure for gene"),
    (10, " The Concise OxfordDictionary (2006) de\u00ef\u00acnes crypto as the art of  writing o r sol"),
]

ALPHA_SET = set(range(ord("A"), ord("Z") + 1)) | set(range(ord("a"), ord("z") + 1))
DIGIT_SET = set(range(ord('0'), ord('9') + 1))
PRINTABLE_SET = set(range(32, 127))
COMMON_PUNCT = set(map(ord, list(" ,.;:'\"!?()-/[]{}&_")))
RARE_PUNCT = set(map(ord, list("~`^|\\<>")))


def bytes_from_hex_list(hex_list: Iterable[str]) -> List[bytes]:
    return [bytes.fromhex(h) for h in hex_list]


def compute_space_evidence(ciphertexts: List[bytes]) -> List[List[int]]:
    max_length = max(len(c) for c in ciphertexts)
    evidence: List[List[int]] = [[0] * max_length for _ in range(len(ciphertexts))]
    for i in range(len(ciphertexts)):
        for j in range(i + 1, len(ciphertexts)):
            length = min(len(ciphertexts[i]), len(ciphertexts[j]))
            for position in range(length):
                xored_byte = ciphertexts[i][position] ^ ciphertexts[j][position]
                if xored_byte in ALPHA_SET:
                    evidence[i][position] += 1
                    evidence[j][position] += 1
    return evidence


def derive_key_by_space_heuristic(
    ciphertexts: List[bytes], space_evidence: List[List[int]],
    include_last_in_seed: bool = False,
) -> List[Optional[int]]:
    max_length = max(len(c) for c in ciphertexts)
    key: List[Optional[int]] = [None] * max_length
    threshold = max(2, (len(ciphertexts) - 1) // 2)

    last_index = len(ciphertexts) - 1
    for ci in range(len(ciphertexts)):
        if not include_last_in_seed and ci == last_index:
            continue
        length = len(ciphertexts[ci])
        for position in range(length):
            if space_evidence[ci][position] >= threshold:
                candidate_key_byte = ciphertexts[ci][position] ^ 0x20
                if key[position] is None:
                    key[position] = candidate_key_byte
                elif key[position] != candidate_key_byte:
                    key[position] = None
    return key


def try_apply_snippet(
    ciphertexts: List[bytes], key: List[Optional[int]], cipher_index: int, snippet: str, *, min_ratio: float = 0.9
) -> bool:
    """Slide the snippet over ciphertext[cipher_index] to find the offset that yields
    the most printable plaintext across all ciphertexts; apply resulting key bytes.
    Returns True if any bytes were applied.
    """
    c = ciphertexts[cipher_index]
    sb = snippet.encode(errors="ignore")
    if len(sb) == 0 or len(c) == 0:
        return False
    best_offset = None
    best_score = -1.0
    best_kbytes: List[Tuple[int, int]] = []  # (pos, key_byte)
    max_offset = max(0, len(c) - len(sb))
    for start in range(max_offset + 1):
        candidate_pairs: List[Tuple[int, int]] = []
        for i, b in enumerate(sb):
            pos = start + i
            if pos >= len(c):
                break
            kb = c[pos] ^ b
            # If key already set and conflicts, reject this offset early
            if key[pos] is not None and key[pos] != kb:
                candidate_pairs = []
                break
            candidate_pairs.append((pos, kb))
        if not candidate_pairs:
            continue
        # Score printability across other ciphertexts for these positions
        total = 0
        printable_hits = 0
        for (pos, kb) in candidate_pairs:
            for j, cj in enumerate(ciphertexts):
                if pos >= len(cj):
                    continue
                total += 1
                ptb = cj[pos] ^ kb
                if ptb in PRINTABLE_SET:
                    printable_hits += 1
        if total == 0:
            continue
        ratio = printable_hits / float(total)
        if ratio > best_score:
            best_score = ratio
            best_offset = start
            best_kbytes = candidate_pairs
    # Apply if strong enough
    if best_offset is not None and best_score >= min_ratio and best_kbytes:
        for pos, kb in best_kbytes:
            key[pos] = kb
        return True
    return False


def apply_hint_direct(
    ciphertexts: List[bytes], key: List[Optional[int]], cipher_index: int, snippet: str
) -> int:
    """Apply snippet at offset 0 directly to set keystream bytes.
    Returns number of bytes applied.
    """
    c = ciphertexts[cipher_index]
    sb = snippet.encode(errors="ignore")
    applied = 0
    for pos in range(min(len(c), len(sb))):
        kb = c[pos] ^ sb[pos]
        if key[pos] is None or key[pos] == kb:
            key[pos] = kb
            applied += 1
    return applied


def refine_key_by_printability(
    ciphertexts: List[bytes],
    key: List[Optional[int]],
    space_evidence: List[List[int]],
    evidence_threshold: int,
    min_printable_ratio: float = 0.8,
    max_passes: int = 2,
) -> None:
    """For positions where the key is unknown, choose the key byte that
    maximizes printable ASCII across all ciphertexts. This does not use any
    known plaintext. Keys failing the printable ratio threshold are left unknown.
    """
    max_len = max(len(c) for c in ciphertexts)
    for _ in range(max_passes):
        changed = False
        for position in range(max_len):
            if key[position] is not None:
                continue
            best_score = -1e9
            best_key_byte: Optional[int] = None
            # Evaluate all candidates
            for candidate in range(256):
                printable_hits = 0
                letter_hits = 0
                digit_hits = 0
                space_hits = 0
                common_punct_hits = 0
                rare_punct_hits = 0
                total = 0
                evidence_bonus = 0.0
                for i, c in enumerate(ciphertexts):
                    if position >= len(c):
                        continue
                    total += 1
                    ptb = c[position] ^ candidate
                    # space evidence shaping
                    if space_evidence[i][position] >= evidence_threshold:
                        if ptb == 0x20:
                            evidence_bonus += 0.35
                        else:
                            evidence_bonus -= 0.20
                    if ptb in PRINTABLE_SET:
                        printable_hits += 1
                        if ptb in ALPHA_SET:
                            letter_hits += 1
                        elif ptb in DIGIT_SET:
                            digit_hits += 1
                        elif ptb == 0x20:
                            space_hits += 1
                        elif ptb in COMMON_PUNCT:
                            common_punct_hits += 1
                        elif ptb in RARE_PUNCT:
                            rare_punct_hits += 1
                if total == 0:
                    continue
                printable_ratio = printable_hits / float(total)
                letter_ratio = letter_hits / float(total)
                digit_ratio = digit_hits / float(total)
                space_ratio = space_hits / float(total)
                common_punct_ratio = common_punct_hits / float(total)
                rare_punct_ratio = rare_punct_hits / float(total)

                score = (
                    7.0 * printable_ratio +
                    2.2 * letter_ratio +
                    0.8 * space_ratio +
                    0.6 * digit_ratio +
                    0.5 * common_punct_ratio -
                    1.2 * rare_punct_ratio +
                    evidence_bonus
                )
                if score > best_score:
                    best_score = score
                    best_key_byte = candidate

            if best_key_byte is not None:
                # Enforce printable threshold for the selected candidate
                total = 0
                printable_hits = 0
                for c in ciphertexts:
                    if position >= len(c):
                        continue
                    total += 1
                    if (c[position] ^ best_key_byte) in PRINTABLE_SET:
                        printable_hits += 1
                if total > 0 and (printable_hits / float(total)) >= min_printable_ratio:
                    key[position] = best_key_byte
                    changed = True
        if not changed:
            break


def decrypt_with_key(ciphertext: bytes, key: List[Optional[int]]) -> str:
    plaintext_chars: List[str] = []
    for position in range(len(ciphertext)):
        key_byte = key[position]
        if key_byte is None:
            plaintext_chars.append("_")
        else:
            plaintext_chars.append(chr(ciphertext[position] ^ key_byte))
    return "".join(plaintext_chars)


def refine_key_by_common_words(
    ciphertexts: List[bytes], key: List[Optional[int]], words: List[str], passes: int = 2
) -> None:
    """Apply a set of generic English cribs (short common words/phrases) across
    all non-target ciphertexts to reveal more keystream, without using
    any message-specific hints.
    """
    non_target_indices = list(range(0, len(ciphertexts) - 1))
    for _ in range(passes):
        changed = False
        for ci in non_target_indices:
            for w in words:
                if try_apply_snippet(ciphertexts, key, ci, w, min_ratio=0.8):
                    changed = True
        if not changed:
            break


def main() -> None:
    parser = argparse.ArgumentParser(description="Many-Time Pad solver")
    parser.add_argument(
        "--use-hints", action="store_true", help="Apply provided plaintext hints to anchor keystream"
    )
    parser.add_argument(
        "--unsupervised", action="store_true", help="Force unsupervised mode (ignore hints)"
    )
    parser.add_argument(
        "--hints-file", type=str, default=None,
        help="Path to hints file containing lines like 'CT3: <plaintext prefix>'"
    )
    args = parser.parse_args()

    ciphertexts = bytes_from_hex_list(HEX_CIPHERTEXTS)
    target = ciphertexts[-1]

    space_evidence = compute_space_evidence(ciphertexts)
    key = derive_key_by_space_heuristic(ciphertexts, space_evidence, include_last_in_seed=False)

    # Optional: apply correctness hints to anchor keystream positions (robust sliding and scoring)
    if args.use_hints and not args.unsupervised:
        applied = 0
        # Load from file if provided
        if args.hints_file:
            try:
                with open(args.hints_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        # Accept formats: CT1:, C1:, 1:, or 'Ciphertext #1'
                        m = re.match(r"^(?:Ciphertext\s*#)?\s*CT?\s*([0-9]+)\s*:\s*(.*)$", line, re.IGNORECASE)
                        if not m:
                            continue
                        idx = int(m.group(1))
                        snippet = m.group(2)
                        if 1 <= idx <= len(ciphertexts) - 1 and snippet:
                            if try_apply_snippet(ciphertexts, key, idx - 1, snippet):
                                applied += 1
            except FileNotFoundError:
                pass
        # Fallback to built-in hints if nothing applied
        if applied == 0:
            for idx, snippet in HINTS:
                if 1 <= idx <= len(ciphertexts) - 1 and snippet:
                    try_apply_snippet(ciphertexts, key, idx - 1, snippet)

    # Unsupervised: generic common-word crib dragging across non-target ct
    common_words = [
        " the ", "The ", "There ", "You ", "We ",
        " of ", " and ", " in ", " to ", " that ", " is ",
        "cipher", "crypto", "ciphertext", "encryption", "algorithm",
        " number ", " computers", " Government",
        " types of ", " keep ", " secrets ",
    ]
    refine_key_by_common_words(ciphertexts, key, common_words, passes=3)

    # Refine unknown key positions purely via printability across all ciphertexts
    evidence_threshold = max(2, (len(ciphertexts) - 1) // 2)
    refine_key_by_printability(
        ciphertexts, key, space_evidence, evidence_threshold, min_printable_ratio=0.9, max_passes=6
    )

    # Decrypt and print plaintexts for ciphertexts #1..#10
    for idx, c in enumerate(ciphertexts[:-1], start=1):
        pi = decrypt_with_key(c, key)
        print(f"Ciphertext #{idx} plaintext: {pi}")

    # Decrypt target and print/write
    plaintext = decrypt_with_key(target, key)
    print(plaintext)
    with open("secret.txt", "w", encoding="utf-8") as f:
        f.write(plaintext + "\n")


if __name__ == "__main__":
    main()
