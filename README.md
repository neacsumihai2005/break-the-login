# AuthX: Secure Login & Ticket Management System

AuthX is a demonstration project designed to showcase the evolution of web security practices. It consists of two versions of a Flask-based application: **v1**, which is intentionally built with numerous critical vulnerabilities for educational purposes, and **v2**, which implements industry-standard security measures to mitigate those risks.

## Project Overview

This repository contains a full-stack authentication and ticketing system. It illustrates the transition from an insecure architecture to a robust, "defense-in-depth" implementation.

### Security Evolution Highlights
| Feature | Version 1 (Vulnerable) | Version 2 (Secured) |
| :--- | :--- | :--- |
| **Password Storage** | Stored in plain text | Hashed with Bcrypt (Salt + Hash) |
| **Password Policy** | No restrictions | Minimum 8 characters required |
| **Brute Force** | Unlimited login attempts | Account locking after 5 failed attempts |
| **User Enumeration**| Specific error messages (e.g., "User not found") | Generic error messages for all failures |
| **Session Security** | 10-year JWT life; no HttpOnly/Secure flags | 60-minute JWT life; HttpOnly & SameSite Lax flags |
| **Data Access** | IDOR: Access any ticket via URL ID | Row-Level Control & RBAC |
| **Secrets** | Hardcoded in source code | Loaded via `.env` environment variables |
| **Logging** | None | Full Audit logs (logins, locks, data access) |

## Repository Structure

* **`scripts/`**: Contains `init_db.py` to set up the PostgreSQL schema (Users, Tickets, and Audit Logs).
* **`v1/`**: The vulnerable application. Includes the Flask app, a vulnerability report (`raport_v1.pdf`), and dependencies.
* **`v2/`**: The secured application. Includes the hardened Flask app, a security implementation report (`raport_v2.pdf`), and updated dependencies.

## Getting Started

### Prerequisites
* Python 3.x
* PostgreSQL database
* `psycopg2-binary`

### Installation
1.  **Clone the repository.**
2.  **Install dependencies**:
    ```bash
    pip install -r v2/requirements.txt
    ```
3.  **Configure Environment**:
    Create a `.env` file in the root directory (based on the `.gitignore` exclusions) and add your database credentials and a secret key:
    ```env
    DB_PASSWORD=your_password
    SECRET_KEY=your_secure_random_key
    ```
4.  **Initialize Database**:
    ```bash
    python scripts/init_db.py
    ```
5.  **Run the Application**:
    Navigate to either `v1/` or `v2/` and run:
    ```bash
    python app.py
    ```

## Core Functionalities
* **Authentication**: Secure registration and login flow.
* **Password Management**: Password reset functionality (Predictable in v1, UUID-based in v2).
* **Ticketing System**: Users can create and view support tickets.
* **Audit Logging (v2)**: Tracks `LOGIN_SUCCESS`, `ACCOUNT_LOCKED`, and `VIEW_TICKETS` for security monitoring.
