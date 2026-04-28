link prezentare: https://www.youtube.com/watch?v=_dVQsZ2s5hc

# AuthX: Sistem Securizat de Autentificare & Management al Tichetelor

AuthX este un proiect demonstrativ conceput pentru a prezenta evoluția practicilor de securitate web. Acesta constă în două versiuni ale unei aplicații bazate pe Flask: **v1**, care este construită intenționat cu numeroase vulnerabilități critice în scopuri educaționale, și **v2**, care implementează măsuri de securitate la standarde industriale pentru a atenua acele riscuri.

## Prezentare Generală a Proiectului

Acest depozit conține un sistem full-stack de autentificare și ticketing. Ilustrează tranziția de la o arhitectură nesigură la o implementare robustă de tip "defense-in-depth".

### Repere ale Evoluției Securității
| Funcționalitate | Versiunea 1 (Vulnerabilă) | Versiunea 2 (Securizată) |
| :--- | :--- | :--- |
| **Stocarea Parolelor** | Stocate în clar (plain text) | Hash-uite cu Bcrypt (Salt + Hash) |
| **Politica de Parole** | Fără restricții | Minim 8 caractere necesare |
| **Brute Force** | Încercări de logare nelimitate | Blocarea contului după 5 încercări eșuate |
| **User Enumeration**| Mesaje de eroare specifice (ex: "Utilizatorul nu exista!") | Mesaje de eroare generice pentru toate eșecurile |
| **Securitatea Sesiunii** | JWT cu durată de viață de 10 ani; fără flag-uri HttpOnly/Secure | JWT cu durată de viață de 60 min; flag-uri HttpOnly & SameSite Lax |
| **Accesul la Date** | IDOR: Accesarea oricărui tichet prin ID-ul din URL | Control la Nivel de Rând (Row-Level Control) & RBAC |
| **Resetare Parolă** | Token predictibil (ex: `reset-email`) | Token JWT securizat (valabilitate 15 minute) |
| **Secrete** | Hardcodate în codul sursă | Încărcate prin variabile de mediu `.env` |
| **Logging** | Inexistent | Loguri complete de audit (logări, blocări, acces date) |

## Structura Depozitului

* **`scripts/`**: Conține `init_db.py` pentru configurarea schemei PostgreSQL (Users, Tickets, și Audit Logs), precum și scripturi pentru simularea atacurilor (`emailfinder.py`, `rockyou.py`).
* **`v1/`**: Aplicația vulnerabilă. Include aplicația Flask și dependențele necesare.
* **`v2/`**: Aplicația securizată. Include aplicația Flask întărită și dependențele actualizate.
* **`prezentare.pdf`**: Raportul complet de securitate care conține demonstrarea atacurilor pe v1 și implementarea fix-urilor din v2.

## Ghid de Pornire

### Cerințe preliminare
* Python 3.x
* Bază de date PostgreSQL
* `psycopg2-binary`

### Instalare
1.  **Clonează depozitul.**
2.  **Instalează dependențele**:
    ```bash
    pip install -r v2/requirements.txt
    ```
3.  **Configurează Mediul**:
    Creează un fișier `.env` în directorul rădăcină (conform regulilor din `.gitignore`) și adaugă credențialele bazei de date și cheia secretă:
    ```env
    DB_PASSWORD=parola_ta
    SECRET_KEY=o_cheie_aleatoare_foarte_sigura
    ```
4.  **Inițializează Baza de Date**:
    ```bash
    python scripts/init_db.py
    ```
5.  **Rulează Aplicația**:
    Navighează fie în `v1/` fie în `v2/` și rulează:
    ```bash
    python app.py
    ```

## Funcționalități de Bază
* **Autentificare**: Flux securizat de înregistrare și logare.
* **Managementul Parolelor**: Funcționalitate de resetare a parolei (predictibilă în v1, bazată pe token JWT în v2).
* **Sistem de Ticketing**: Utilizatorii pot crea și vizualiza tichete de suport, accesul fiind filtrat securizat (RBAC) în v2.
* **Audit Logging (v2)**: Urmărește `LOGIN_SUCCESS`, `ACCOUNT_LOCKED`, și `VIEW_TICKETS` pentru monitorizarea continuă a securității.
