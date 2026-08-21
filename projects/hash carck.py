import hashlib
import argparse

def compute_hash(text, algo="md5"):
    h = hashlib.new(algo)
    h.update(text.encode())
    return h.hexdigest()

def crack_hash(hash_value, wordlist_file, algo="md5"):
    with open(wordlist_file, 'r') as f:
        for line in f:
            word = line.strip()
            if compute_hash(word, algo) == hash_value:
                return word
    return None

LENGTH_TO_ALGO = {
    32:  "md5",
    40:  "sha1",
    56:  "sha224",
    64:  "sha256",
    96:  "sha384",
    128: "sha512",
}

def guess_algorithm(hash_str: str) -> str:
    length = len(hash_str.strip())
    algo = LENGTH_TO_ALGO.get(length)
    if algo is None:
        raise argparse.ArgumentTypeError(
            f"Can't guess algorithm for a {length}-char hash. "
            f"Pass --algo explicitly."
        )
    return algo

parser = argparse.ArgumentParser(description="algo hash cracker")
parser.add_argument("--wordlist", default="C:/Users/PC/Downloads/malenames-usa-top1000.txt", help="Path to the wordlist file")
parser.add_argument("--hash", required=True, help="Hash value to crack")
parser.add_argument("--algo", default=None, help="Hash algorithm (auto-detected from hash length if omitted)")
args = parser.parse_args()

algo = args.algo or guess_algorithm(args.hash)
if not args.algo:
    print(f"[i] No --algo given — guessed '{algo}' from hash length")

result = crack_hash(args.hash, args.wordlist, algo)
if result:
    print(f"Hash cracked! The original text is: {result}")
else:
    print("Hash not found in the wordlist.")