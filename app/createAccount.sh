#!/bin/sh

set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PYTHON="$PROJECT_DIR/.venv/bin/python"
PASSWORD_FILE="$SCRIPT_DIR/password.txt"

if [ ! -x "$PYTHON" ]; then
    echo "Python was not found at: $PYTHON"
    exit 1
fi

if [ ! -f "$PASSWORD_FILE" ]; then
    echo "Password file was not found at: $PASSWORD_FILE"
    exit 1
fi

"$PYTHON" - "$SCRIPT_DIR" "$PASSWORD_FILE" <<'PYTHON'
import sqlite3
import sys
from pathlib import Path

from werkzeug.security import generate_password_hash


app_directory = Path(sys.argv[1]).resolve()
password_file = Path(sys.argv[2]).resolve()

sys.path.insert(0, str(app_directory))

import app as app_module


def read_accounts(path):
    accounts = []

    for line_number, original_line in enumerate(
        path.read_text().splitlines(),
        start=1,
    ):
        line = original_line.strip()

        if (
            not line
            or line.startswith("personID")
            or line.startswith("#")
        ):
            continue

        pieces = [
            piece.strip()
            for piece in line.split("|")
        ]

        if len(pieces) != 4:
            raise RuntimeError(
                f"Invalid password.txt format "
                f"on line {line_number}"
            )

        (
            person_id_text,
            email,
            password,
            reference_role,
        ) = pieces

        try:
            person_id = int(person_id_text)
        except ValueError as error:
            raise RuntimeError(
                f"Invalid personID on line {line_number}"
            ) from error

        email = email.lower()

        if not email or "@" not in email:
            raise RuntimeError(
                f"Invalid email for person {person_id}"
            )

        if len(password) < 10:
            raise RuntimeError(
                f"Password for person {person_id} "
                f"is too short"
            )

        if reference_role not in ("User", "Employee"):
            raise RuntimeError(
                f"Invalid reference role for "
                f"person {person_id}"
            )

        accounts.append(
            {
                "personID": person_id,
                "email": email,
                "password": password,
                "referenceRole": reference_role,
            }
        )

    return accounts


accounts = read_accounts(password_file)

if not accounts:
    raise RuntimeError(
        "No accounts were found in password.txt"
    )


with app_module.app.app_context():
    db = app_module.get_db()

    created = 0
    skipped = 0

    try:
        with db:
            for account in accounts:
                person_id = account["personID"]
                email = account["email"]
                password = account["password"]

                person = db.execute(
                    """
                    SELECT
                        personID,
                        firstName,
                        lastName,
                        email
                    FROM Person
                    WHERE personID = ?
                      AND email = ?
                    """,
                    (
                        person_id,
                        email,
                    ),
                ).fetchone()

                if person is None:
                    raise RuntimeError(
                        f"Person {person_id} does not exist "
                        f"or the email does not match"
                    )

                employee = db.execute(
                    """
                    SELECT employeeID
                    FROM Employee
                    WHERE personID = ?
                    """,
                    (person_id,),
                ).fetchone()

                account_role = (
                    "Employee"
                    if employee is not None
                    else "User"
                )

                if (
                    account["referenceRole"]
                    != account_role
                ):
                    raise RuntimeError(
                        f"Role in password.txt does not "
                        f"match the database for "
                        f"person {person_id}"
                    )

                existing_account = db.execute(
                    """
                    SELECT accountID
                    FROM Auth
                    WHERE personID = ?
                    """,
                    (person_id,),
                ).fetchone()

                if existing_account is not None:
                    print(
                        f"Skipped person {person_id}: "
                        f"account already exists"
                    )

                    skipped += 1
                    continue

                password_hash = generate_password_hash(
                    password,
                    method="pbkdf2:sha256",
                )

                db.execute(
                    """
                    INSERT INTO Auth
                    (
                        personID,
                        passwordHash,
                        accountRole,
                        createdAt
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        person_id,
                        password_hash,
                        account_role,
                        app_module.currentTime(),
                    ),
                )

                full_name = (
                    f"{person['firstName']} "
                    f"{person['lastName']}"
                )

                print(
                    f"Created {account_role} account: "
                    f"person {person_id}, "
                    f"{full_name}, "
                    f"{person['email']}"
                )

                created += 1

    except sqlite3.IntegrityError as error:
        raise RuntimeError(
            app_module.db_error(error)
        ) from error


print()
print(f"Created: {created}")
print(f"Skipped: {skipped}")
print(f"Total in password file: {len(accounts)}")
PYTHON