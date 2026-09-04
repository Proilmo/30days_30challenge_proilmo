import requests
import threading
import queue
import random
import string

# Status codes we consider "interesting" (worth reporting)
INTERESTING_CODES = {200, 301, 302, 403}

THREAD_COUNT = 20
TIMEOUT = 5


def get_baseline(session, base_url):
    """
    Request a random, almost-certainly-nonexistent path.
    If the server returns 200 for it, it's a wildcard/catch-all
    responder, and we need to compare future 200s against this
    baseline's content length instead of trusting the status code alone.
    """
    fake_path = "".join(random.choices(string.ascii_lowercase, k=16))
    fake_url = base_url + fake_path
    try:
        resp = session.get(fake_url, timeout=TIMEOUT)
        return resp.status_code, len(resp.content)
    except requests.exceptions.RequestException:
        return None, None


def worker(q, session, base_url, baseline_status, baseline_length, print_lock):
    while True:
        try:
            directory = q.get_nowait()
        except queue.Empty:
            return

        directory_url = base_url + directory

        try:
            response = session.get(directory_url, timeout=TIMEOUT, allow_redirects=False)
        except requests.exceptions.ConnectionError:
            q.task_done()
            continue
        except requests.exceptions.Timeout:
            q.task_done()
            continue
        except requests.exceptions.TooManyRedirects:
            q.task_done()
            continue
        except requests.exceptions.RequestException:
            # catch-all for anything else requests might raise
            q.task_done()
            continue

        status = response.status_code

        if status in INTERESTING_CODES:
            # If the server is a wildcard-responder (baseline was 200),
            # only flag this result if it *differs* from the baseline
            # in length -- otherwise it's just the same catch-all page.
            if baseline_status == 200 and status == 200:
                if len(response.content) == baseline_length:
                    q.task_done()
                    continue

            with print_lock:
                print(f"[+] {status} - {directory_url} (len={len(response.content)})")

        q.task_done()


def main():
    url = input("Enter the URL to brute-force: ").strip()
    wordlist_path = input("Enter the path of the wordlist: ").strip()

    # Normalize the base URL so we never get "//" or missing "/" bugs
    base_url = url.rstrip("/") + "/"

    with open(wordlist_path, "r") as f:
        wordlist = f.read().splitlines()

    session = requests.Session()

    print("[*] Checking for wildcard responses...")
    baseline_status, baseline_length = get_baseline(session, base_url)
    if baseline_status == 200:
        print(f"[!] Wildcard response detected (status 200, length={baseline_length}). "
              f"Filtering matches with the same length.")
    else:
        print("[*] No wildcard response detected.")

    q = queue.Queue()
    for directory in wordlist:
        directory = directory.strip()
        if directory:
            q.put(directory)

    print_lock = threading.Lock()
    threads = []

    print(f"[*] Starting scan with {THREAD_COUNT} threads...")
    for _ in range(THREAD_COUNT):
        t = threading.Thread(
            target=worker,
            args=(q, session, base_url, baseline_status, baseline_length, print_lock)
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("[*] Scan complete.")


if __name__ == "__main__":
    main()