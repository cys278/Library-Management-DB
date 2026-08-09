import os
import secrets
import sqlite3
import click
from datetime import date, datetime, timedelta
from functools import wraps
from getpass import getpass
from pathlib import Path
from dotenv import load_dotenv
from flask import (
    Flask, 
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

# Refernce: https://werkzeug.palletsprojects.com/en/stable/utils/#module-werkzeug.security
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

load_dotenv(BASE_DIR / ".env")

app = Flask(__name__)

library_db = os.getenv("LIBRARY_DB", "../library.db")

app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY"),
    LIBRARY_DB=str((BASE_DIR/library_db).resolve()),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
)

if not app.config["SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY is missing")

LIBRARY_ITEM_TYPES = (
    "Print Book",
    "Online Book",
    "Magazine",
    "Scientific Journal",
    "Record",
    "Laptop",
    "Charger",
    "Marker",
    "Eraser",
)

PHYSICAL_ITEM_TYPES = tuple(
    item_type
    for item_type in LIBRARY_ITEM_TYPES
    if item_type != "Online Book"
)

VOLUNTEER_ROLES = (
    "Registration Assistant",
    "Room Setup",
    "Event Guide",
    "Cleanup Assistant",
)

EVENT_TYPES = (
    "Book Club",
    "Author Talk",
    "Book Workshop",
    "Art Show",
    "Film Screening",
    "Cultural Festival",
    "Gaming Event",
    "Group Meeting",
)
        
def get_db():
    if "db" not in g:
        db_path = Path(app.config["LIBRARY_DB"])
        
        if not db_path.exists():
            raise RuntimeError(f"library.db does not exist at {db_path}")
        
        connection = sqlite3.connect(db_path, timeout=10, detect_types=sqlite3.PARSE_DECLTYPES)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        g.db = connection
        
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop("db", None)
    
    if connection is not None:
        connection.close()
        
def currentTime():
    return datetime.now().replace(second=0, microsecond=0).strftime("%Y-%m-%d %H:%M")

def currentDate():
    return date.today().isoformat()

def db_error(error):
    message = str(error)
    
    changes = {
        "UNIQUE constraint failed: Person.email":
            "Account already exists with this email",
        "UNIQUE constraint failed: Auth.personID":
            "This person already has an account",
        "UNIQUE constraint failed: EventRegistration.personID, EventRegistration.eventID":
            "You already have registerd for event",
        "UNIQUE constraint failed: VolunteerAssignment.personID, VolunteerAssignment.eventID, VolunteerAssignment.role":
            "You already applied for this volunteer role",
        "FOREIGN KEY constraint failed":
            "The selected record no longer exists",
    }
    
    for org, change in changes.items():
        if org in message:
            return change
    
    if len(message) <= 180:
        return message
    
    return "Database coould not complete your request"

def dueDateTime(item_type, borrowed_at):
    if item_type in (
        "Print Book",
        "Magazine",
        "Scientific Journal",
        "Record",
    ): 
        return borrowed_at + timedelta(days=21)
    
    if item_type == "Laptop":
        return borrowed_at + timedelta(hours=24)
    
    if item_type in (
        "Charger",
        "Marker",
        "Eraser",
    ):
        return borrowed_at + timedelta(hours=4)
    
    raise ValueError("You can only borrow borrowable items")


@app.before_request
def accAndCheckCSRF():
    g.account = None
    g.employee = None

    account_id = session.get("account_id")

    if account_id:
        g.account = get_db().execute(
            """
            SELECT a.accountID, a.personID, a.accountRole, p.email
            FROM Auth a
            JOIN Person p ON p.personID = a.personID
            WHERE a.accountID = ?
            """,
            (account_id,),
        ).fetchone()

    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)

    if request.method == "POST":
        submitted = request.form.get("_csrf_token", "")
        expected = session.get("_csrf_token", "")

        if not secrets.compare_digest(submitted, expected):
            abort(400, "Invalid or expired form submission.")


@app.context_processor
def templateValues():
    return {
        "csrf_token": session.get("_csrf_token"),
        "library_item_types": LIBRARY_ITEM_TYPES,
        "physical_item_types": PHYSICAL_ITEM_TYPES,
        "volunteer_roles": VOLUNTEER_ROLES,
        "event_types": EVENT_TYPES,
    }


def loginRequired(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.account is None:
            flash("Please log in first", "error")
            return redirect(url_for("login", next=request.path))

        return view(*args, **kwargs)

    return wrapped


def userRequired(view):
    @wraps(view)
    @loginRequired
    def wrapped(*args, **kwargs):
        if g.account["accountRole"] != "User":
            abort(403)

        return view(*args, **kwargs)

    return wrapped


def employeeRequired(*allowed_positions):
    def decorator(view):
        @wraps(view)
        @loginRequired
        def wrapped(*args, **kwargs):
            if g.account["accountRole"] != "Employee":
                abort(403)

            employee = get_db().execute(
                """
                SELECT
                    e.employeeID,
                    e.position,
                    e.employeeStatus,
                    p.firstName,
                    p.lastName
                FROM Employee e
                JOIN Person p ON p.personID = e.personID
                WHERE e.personID = ?
                """,
                (g.account["personID"],),
            ).fetchone()

            if employee is None:
                abort(403)

            if employee["employeeStatus"] != "Active":
                flash("Only active employees can use employee dashboard", "error")
                return redirect(url_for("logoutPage"))

            if (
                allowed_positions
                and employee["position"] not in allowed_positions
            ):
                abort(403)

            g.employee = employee
            return view(*args, **kwargs)

        return wrapped

    return decorator

@app.route("/")
def index():
    if g.account is None:
        return redirect(url_for("login"))
    
    if g.account["accountRole"] == "Employee":
        return redirect(url_for("employee_Dashboard"))
    
    return redirect(url_for("home"))

@app.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        
        account = get_db().execute(
            """
            SELECT a.accountID, a.personID, a.passwordHash, a.accountRole, p.email 
            FROM Auth a
            JOIN Person p ON p.personID = a.personID
            WHERE p.email = ?
            """,
            (email,), 
        ).fetchone()
        
        if (account is None or not check_password_hash(account["passwordHash"], password)):
            flash("Email or password is incorrect", "error")
            return render_template("login.html")
        
        if account["accountRole"] == "Employee":
            employee = get_db().execute(
                """
                SELECT employeeStatus
                FROM employee
                WHERE personID = ?
                """,
                (account["personID"],),
            ).fetchone()
            
            if employee is None or employee["employeeStatus"] != "Active":
                flash("Your employee account is not active", "error")
                return render_template("login.html")
            
        session.clear()
        session["_csrf_token"] = secrets.token_urlsafe(32)
        session["account_id"] = account["accountID"]
        
        if account["accountRole"] == "Employee":
            return redirect(url_for("employee_Dashboard"))
        
        return redirect(url_for("home"))
    
    return render_template("login.html")


@app.route("/create-account", methods=("GET", "POST"))
def createAccount():
    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone_number = request.form.get("phone_number", "").strip() or None
        address = request.form.get("address", "").strip() or None
        date_of_birth = request.form.get("date_of_birth", "").strip() or None
        password = request.form.get("password", "")
        confirmation = request.form.get("confirmation", "")
        
        if not first_name or not last_name:
            flash("First name and Last name are required", "error")
            return render_template("createAccount.html")

        if not email or "@" not in email:
            flash("Enter valid email address", "error")
            return render_template("createAccount.html")

        if len(password) < 10:
            flash("Password must have at least 10 characters", "error")
            return render_template("createAccount.html")

        if password != confirmation:
            flash("Password do not match", "error")
            return render_template("createAccount.html")

        db = get_db()

        try:
            with db:
                cursor = db.execute(
                    """
                    INSERT INTO PERSON
                    (
                        firstName,
                        lastName,
                        email,
                        phoneNumber,
                        address,
                        dateOfBirth
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        first_name,
                        last_name,
                        email,
                        phone_number,
                        address,
                        date_of_birth
                    ),
                )
                
                person_id = cursor.lastrowid
                
                db.execute(
                    """
                    INSERT INTO Auth
                    (
                        personID,
                        passwordHash,
                        accountRole,
                        createdAt
                    )
                    VALUES (?, ?, 'User', ?)
                    """,
                    (
                        person_id,
                        generate_password_hash(password, method="pbkdf2:sha256"),
                        currentTime(),
                    ),
                )

            flash("Your account is ready. You can log in now", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError as error:
            flash(db_error(error), "error")

    return render_template("createAccount.html")


@app.post("/logout")
@loginRequired
def logout():
    session.clear()
    flash("You have logged out", "success")
    return redirect(url_for("login"))


@app.route("/logged-out")
def logoutPage():
    session.clear()
    return redirect(url_for("login"))


@app.route("/home")
@userRequired
def home():
    db = get_db()
    person_id = g.account["personID"]

    person = db.execute(
        """
        SELECT
            p.*,
            m.memberID,
            m.membershipDate,
            m.membershipStatus
        FROM Person p
        LEFT JOIN Member m ON m.personID = p.personID
        WHERE p.personID = ?
        """,
        (person_id,),
    ).fetchone()

    active_loans = db.execute(
        """
        SELECT COUNT(*) AS total
        FROM Loan l
        JOIN Member m ON m.memberID = l.memberID
        WHERE m.personID = ?
          AND l.returnDateTime IS NULL
        """,
        (person_id,),
    ).fetchone()["total"]

    unpaid_fines = db.execute(
        """
        SELECT COALESCE(SUM(f.amount), 0) AS total
        FROM Fine f
        JOIN Loan l ON l.loanID = f.loanID
        JOIN Member m ON m.memberID = l.memberID
        WHERE m.personID = ?
          AND f.paymentStatus = 'Unpaid'
        """,
        (person_id,),
    ).fetchone()["total"]

    return render_template(
        "home.html",
        person=person,
        active_loans=active_loans,
        unpaid_fines=unpaid_fines,
    )
    
@app.route("/items")
@loginRequired
def items():
    search = request.args.get("q", "").strip()
    item_type = request.args.get("type", "").strip()

    conditions = []
    values = []

    if search:
        pattern = f"%{search}%"

        conditions.append(
            """
            (
                li.itemTitle LIKE ?
                OR COALESCE(li.author, '') LIKE ?
                OR COALESCE(li.ISBN, '') LIKE ?
            )
            """
        )
        values.extend((pattern, pattern, pattern))

    if item_type:
        conditions.append("li.itemType = ?")
        values.append(item_type)

    where_part = ""

    if conditions:
        where_part = "WHERE " + " AND ".join(conditions)

    item_rows = get_db().execute(
        f"""
        SELECT
            li.*,
            COUNT(bi.borrowableItemID) AS totalCopies,

            SUM(
                CASE
                    WHEN bi.itemStatus = 'Available' THEN 1
                    ELSE 0
                END
            ) AS availableCopies,

            SUM(
                CASE
                    WHEN bi.itemStatus = 'Borrowed' THEN 1
                    ELSE 0
                END
            ) AS borrowedCopies,

            SUM(
                CASE
                    WHEN bi.itemStatus = 'Maintenance' THEN 1
                    ELSE 0
                END
            ) AS maintenanceCopies,

            SUM(
                CASE
                    WHEN bi.itemStatus = 'Lost' THEN 1
                    ELSE 0
                END
            ) AS lostCopies

        FROM LibraryItem li
        LEFT JOIN BorrowableItem bi ON bi.itemID = li.itemID
        {where_part}
        GROUP BY li.itemID
        ORDER BY li.itemTitle
        """,
        values,
    ).fetchall()

    return render_template(
        "items.html",
        items=item_rows,
        search=search,
        selected_type=item_type,
    )


@app.post("/items/<int:item_id>/borrow")
@userRequired
def borrowItem(item_id):
    db = get_db()

    member = db.execute(
        """
        SELECT memberID, membershipStatus
        FROM Member
        WHERE personID = ?
        """,
        (g.account["personID"],),
    ).fetchone()

    if member is None:
        flash("You need to be library member to borrow items", "error")
        return redirect(url_for("items"))

    item = db.execute(
        """
        SELECT itemID, itemTitle, itemType
        FROM LibraryItem
        WHERE itemID = ?
        """,
        (item_id,),
    ).fetchone()

    if item is None:
        abort(404)

    if item["itemType"] == "Online Book":
        flash("Online books are opened using their PDF link", "error")
        return redirect(url_for("items"))

    copy = db.execute(
        """
        SELECT borrowableItemID, barcode
        FROM BorrowableItem
        WHERE itemID = ?
          AND itemStatus = 'Available'
        ORDER BY
            CASE itemCondition
                WHEN 'New' THEN 1
                WHEN 'Good' THEN 2
                WHEN 'Fair' THEN 3
                ELSE 4
            END,
            borrowableItemID
        LIMIT 1
        """,
        (item_id,),
    ).fetchone()

    if copy is None:
        flash("No available copy is found", "error")
        return redirect(url_for("items"))

    borrowed_at = datetime.now().replace(second=0, microsecond=0)

    try:
        due_at = dueDateTime(item["itemType"], borrowed_at)

        with db:
            db.execute(
                """
                INSERT INTO Loan
                (
                    memberID,
                    borrowableItemID,
                    employeeID,
                    borrowDateTime,
                    dueDateTime,
                    returnDateTime
                )
                VALUES (?, ?, NULL, ?, ?, NULL)
                """,
                (
                    member["memberID"],
                    copy["borrowableItemID"],
                    borrowed_at.strftime("%Y-%m-%d %H:%M"),
                    due_at.strftime("%Y-%m-%d %H:%M"),
                ),
            )

        flash(
            f"{item['itemTitle']} is borrowed. "
            f"Due date is {due_at:%Y-%m-%d %H:%M}",
            "success",
        )

        return redirect(url_for("loans"))

    except (sqlite3.IntegrityError, ValueError) as error:
        flash(db_error(error), "error")
        return redirect(url_for("items"))
    
@app.route("/loans")
@userRequired
def loans():
    loan_rows = get_db().execute(
        """
        SELECT
            l.*,
            li.itemTitle,
            li.itemType,
            bi.barcode,
            bi.itemStatus,
            f.amount,
            f.paymentStatus,
            f.paymentDate,
            f.description AS fineDescription
        FROM Member m
        JOIN Loan l ON l.memberID = m.memberID
        JOIN BorrowableItem bi
            ON bi.borrowableItemID = l.borrowableItemID
        JOIN LibraryItem li ON li.itemID = bi.itemID
        LEFT JOIN Fine f ON f.loanID = l.loanID
        WHERE m.personID = ?
        ORDER BY
            (l.returnDateTime IS NULL) DESC,
            l.borrowDateTime DESC
        """,
        (g.account["personID"],),
    ).fetchall()

    return render_template("loans.html", loans=loan_rows)


@app.post("/loans/<int:loan_id>/return")
@userRequired
def returnItem(loan_id):
    db = get_db()

    loan = db.execute(
        """
        SELECT l.loanID
        FROM Loan l
        JOIN Member m ON m.memberID = l.memberID
        WHERE l.loanID = ?
          AND m.personID = ?
          AND l.returnDateTime IS NULL
        """,
        (loan_id, g.account["personID"]),
    ).fetchone()

    if loan is None:
        abort(404)

    try:
        with db:
            db.execute(
                """
                UPDATE Loan
                SET returnDateTime = ?
                WHERE loanID = ?
                """,
                (currentTime(), loan_id),
            )

        fine = db.execute(
            """
            SELECT amount
            FROM Fine
            WHERE loanID = ?
            """,
            (loan_id,),
        ).fetchone()

        if fine:
            flash(
                f"Item returned. Overdue fine is "
                f"${fine['amount']:.2f}",
                "warning",
            )
        else:
            flash("Item returned successfully", "success")

    except sqlite3.IntegrityError as error:
        flash(db_error(error), "error")

    return redirect(url_for("loans"))

@app.route("/donate", methods=("GET", "POST"))
@userRequired
def donate():
    if request.method == "POST":
        titles = request.form.getlist("title")
        item_types = request.form.getlist("item_type")
        authors = request.form.getlist("author")
        quantities = request.form.getlist("quantity")
        conditions = request.form.getlist("condition")
        
        field_length = {
            len(titles),
            len(item_types),
            len(authors),
            len(quantities),
            len(conditions),
        }
        
        if len(field_length) != 1:
            flash("Donated item information is missing", "error")
            return render_template("donate.html")

        items_to_donate = []

        for index, title in enumerate(titles):
            title = title.strip()

            if not title:
                continue

            try:
                quantity = int(quantities[index])
            except (ValueError, IndexError):
                quantity = 0

            if quantity <= 0:
                flash("Every donated item need positive quantity", "error")
                return render_template("donate.html")

            author = authors[index].strip() or None
            condition = conditions[index] or None

            items_to_donate.append(
                (
                    title,
                    item_types[index],
                    author,
                    quantity,
                    condition,
                )
            )

        if not items_to_donate:
            flash("Add at least one item", "error")
            return render_template("donate.html")

        db = get_db()

        try:
            with db:
                cursor = db.execute(
                    """
                    INSERT INTO Donation
                    (
                        donorPersonID,
                        reviewEmployeeID,
                        donationDate,
                        donationStatus
                    )
                    VALUES (?, NULL, ?, 'Pending')
                    """,
                    (
                        g.account["personID"],
                        currentDate(),
                    ),
                )

                donation_id = cursor.lastrowid

                for item in items_to_donate:
                    db.execute(
                        """
                        INSERT INTO DonatedItems
                        (
                            donationID,
                            title,
                            itemType,
                            author,
                            quantity,
                            itemCondition,
                            approvalStatus
                        )
                        VALUES (?, ?, ?, ?, ?, ?, 'Pending')
                        """,
                        (donation_id, *item),
                    )

            flash(
                f"Donation {donation_id} is submitted for review",
                "success",
            )

            return redirect(url_for("home"))

        except sqlite3.IntegrityError as error:
            flash(db_error(error), "error")

    return render_template("donate.html")

def ageGroups(date_of_birth, event_date):
    if not date_of_birth or not event_date:
        return set()
    
    try: 
        birth = date.fromisoformat(date_of_birth)
        event_day = date.fromisoformat(event_date)
    except(TypeError, ValueError):
        return set()

    age = event_day.year - birth.year

    if (event_day.month, event_day.day) < (birth.month, birth.day):
        age -= 1
        
    if age < 0:
        return set()

    if age <= 12:
        return {"Children", "Families"}

    if age <= 19:
        return {"Teenagers", "Young Adults"}

    if age <= 34:
        return {"Young Adults", "Adults"}

    if age <= 64:
        return {"Adults"}

    return {"Seniors"}


@app.route("/events")
@loginRequired
def events():
    db = get_db()
    search = request.args.get("q", "").strip()

    values = [g.account["personID"]]
    where_part = ""

    if search:
        pattern = f"%{search}%"

        where_part = """
        WHERE (
            e.eventName LIKE ?
            OR e.eventType LIKE ?
            OR COALESCE(e.description, '') LIKE ?
        )
        """

        values.extend((pattern, pattern, pattern))

    event_rows = db.execute(
        f"""
        SELECT
            e.*,
            r.roomName,

            (
                SELECT COUNT(*)
                FROM EventRegistration er
                WHERE er.eventID = e.eventID
                  AND er.registrationStatus <> 'Cancelled'
            ) AS registrationCount,

            (
                SELECT GROUP_CONCAT(a.audienceName, ', ')
                FROM EventAudience ea
                JOIN Audience a ON a.audienceID = ea.audienceID
                WHERE ea.eventID = e.eventID
            ) AS audiences,

            EXISTS (
                SELECT 1
                FROM EventInterest ei
                JOIN PersonInterest pi
                    ON pi.interestID = ei.interestID
                WHERE ei.eventID = e.eventID
                  AND pi.personID = ?
            ) AS interestMatch

        FROM Event e
        JOIN Room r ON r.roomID = e.roomID
        {where_part}
        ORDER BY e.eventDate, e.startTime
        """,
        values,
    ).fetchall()

    person = db.execute(
        """
        SELECT dateOfBirth
        FROM Person
        WHERE personID = ?
        """,
        (g.account["personID"],),
    ).fetchone()

    event_list = []

    for row in event_rows:
        event = dict(row)

        audience_names = {
            name.strip()
            for name in (event["audiences"] or "").split(",")
            if name.strip()
        }
        
        date_of_birth = (
            person["dateOfBirth"]
            if person is not None
            else None
        )

        suitable_age_groups = ageGroups(
            date_of_birth,
            event["eventDate"],
        )

        event["recommended"] = bool(
            event["interestMatch"]
            or audience_names.intersection(suitable_age_groups)
        )

        event_list.append(event)

    return render_template(
        "events.html",
        events=event_list,
        search=search,
    )


@app.post("/events/<int:event_id>/register")
@userRequired
def registerEvent(event_id):
    try:
        with get_db():
            get_db().execute(
                """
                INSERT INTO EventRegistration
                (
                    personID,
                    eventID,
                    registrationDate,
                    registrationStatus
                )
                VALUES (?, ?, ?, 'Registered')
                """,
                (
                    g.account["personID"],
                    event_id,
                    currentDate(),
                ),
            )

        flash("You are registered for this event", "success")

    except sqlite3.IntegrityError as error:
        flash(db_error(error), "error")

    return redirect(url_for("events"))


@app.post("/events/<int:event_id>/volunteer")
@userRequired
def volunteerEvent(event_id):
    role = request.form.get("role", "")

    if role not in VOLUNTEER_ROLES:
        abort(400)

    event = get_db().execute(
        """
        SELECT eventStatus
        FROM Event
        WHERE eventID = ?
        """,
        (event_id,),
    ).fetchone()

    if event is None:
        abort(404)

    if event["eventStatus"] != "Open":
        flash("Volunteer applications are closed for this event", "error")
        return redirect(url_for("events"))

    try:
        with get_db():
            get_db().execute(
                """
                INSERT INTO VolunteerAssignment
                (
                    role,
                    personID,
                    eventID,
                    status,
                    numberOfHours
                )
                VALUES (?, ?, ?, 'Pending', 0)
                """,
                (
                    role,
                    g.account["personID"],
                    event_id,
                ),
            )

        flash("Volunteer application is submitted", "success")

    except sqlite3.IntegrityError as error:
        flash(db_error(error), "error")

    return redirect(url_for("events"))

@app.route("/help", methods=("GET", "POST"))
@userRequired
def helpRequest():
    db = get_db()

    if request.method == "POST":
        issue = request.form.get("issue", "").strip()
        message = request.form.get("message", "").strip()

        if not issue or not message:
            flash("Issue and message is required", "error")
        else:
            with db:
                db.execute(
                    """
                    INSERT INTO HelpRequest
                    (
                        personID,
                        issue,
                        messages,
                        requestStatus,
                        createdAt
                    )
                    VALUES (?, ?, ?, 'Open', ?)
                    """,
                    (
                        g.account["personID"],
                        issue,
                        message,
                        currentTime(),
                    ),
                )

            flash("Your question is sent to librarian", "success")
            return redirect(url_for("helpRequest"))

    help_rows = db.execute(
        """
        SELECT *
        FROM HelpRequest
        WHERE personID = ?
        ORDER BY createdAt DESC
        """,
        (g.account["personID"],),
    ).fetchall()

    return render_template(
        "help.html",
        help_requests=help_rows,
    )
    
@app.route("/acquisition-request", methods=("GET", "POST"))
@userRequired
def acquisitionRequest():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        item_type = request.form.get("item_type", "").strip()
        author = request.form.get("author", "").strip() or None

        try:
            quantity = int(request.form.get("quantity", "0"))

            cost_value = request.form.get(
                "estimated_cost",
                "",
            ).strip()

            estimated_cost = (
                float(cost_value)
                if cost_value
                else None
            )

        except ValueError:
            flash("Quantity or estimated cost is invalid", "error")
            return render_template("acquisitionRequest.html")

        if not title:
            flash("Title is required", "error")
            return render_template("acquisitionRequest.html")

        if quantity <= 0:
            flash("Quantity must be greater than zero", "error")
            return render_template("acquisitionRequest.html")

        try:
            with get_db():
                get_db().execute(
                    """
                    INSERT INTO FutureAcquisitions
                    (
                        title,
                        itemType,
                        author,
                        proposedQuantity,
                        estimatedCost,
                        requestDate,
                        requestStatus,
                        personID,
                        employeeID
                    )
                    VALUES (?, ?, ?, ?, ?, ?, 'Proposed', ?, NULL)
                    """,
                    (
                        title,
                        item_type,
                        author,
                        quantity,
                        estimated_cost,
                        currentDate(),
                        g.account["personID"],
                    ),
                )

            flash("Acquisition request is submitted", "success")
            return redirect(url_for("home"))

        except sqlite3.IntegrityError as error:
            flash(db_error(error), "error")

    return render_template("acquisitionRequest.html")

@app.route("/employee")
@employeeRequired()
def employee_Dashboard():
    db = get_db()

    active_loans = db.execute(
        """
        SELECT
            l.loanID,
            l.borrowDateTime,
            l.dueDateTime,
            li.itemTitle,
            li.itemType,
            bi.barcode,
            p.firstName || ' ' || p.lastName AS memberName
        FROM Loan l
        JOIN Member m ON m.memberID = l.memberID
        JOIN Person p ON p.personID = m.personID
        JOIN BorrowableItem bi
            ON bi.borrowableItemID = l.borrowableItemID
        JOIN LibraryItem li ON li.itemID = bi.itemID
        WHERE l.returnDateTime IS NULL
        ORDER BY l.dueDateTime
        """
    ).fetchall()

    unpaid_fines = db.execute(
        """
        SELECT
            f.fineID,
            f.loanID,
            f.amount,
            f.issueDate,
            p.firstName || ' ' || p.lastName AS memberName,
            li.itemTitle
        FROM Fine f
        JOIN Loan l ON l.loanID = f.loanID
        JOIN Member m ON m.memberID = l.memberID
        JOIN Person p ON p.personID = m.personID
        JOIN BorrowableItem bi
            ON bi.borrowableItemID = l.borrowableItemID
        JOIN LibraryItem li ON li.itemID = bi.itemID
        WHERE f.paymentStatus = 'Unpaid'
        ORDER BY f.issueDate
        """
    ).fetchall()

    donations = db.execute(
        """
        SELECT
            d.*,
            p.firstName || ' ' || p.lastName AS donorName
        FROM Donation d
        JOIN Person p ON p.personID = d.donorPersonID
        ORDER BY d.donationDate DESC
        """
    ).fetchall()

    donated_items = db.execute(
        """
        SELECT *
        FROM DonatedItems
        ORDER BY donationID, donatedItemID
        """
    ).fetchall()

    donated_by_donation = {}

    for item in donated_items:
        donated_by_donation.setdefault(
            item["donationID"],
            [],
        ).append(item)

    acquisitions = db.execute(
        """
        SELECT
            fa.*,
            p.firstName || ' ' || p.lastName AS requesterName
        FROM FutureAcquisitions fa
        JOIN Person p ON p.personID = fa.personID
        ORDER BY fa.requestDate DESC
        """
    ).fetchall()

    event_rows = db.execute(
        """
        SELECT e.*, r.roomName
        FROM Event e
        JOIN Room r ON r.roomID = e.roomID
        ORDER BY e.eventDate, e.startTime
        """
    ).fetchall()

    copies = db.execute(
        """
        SELECT
            bi.*,
            li.itemTitle,
            li.itemType
        FROM BorrowableItem bi
        JOIN LibraryItem li ON li.itemID = bi.itemID
        ORDER BY li.itemTitle, bi.barcode
        """
    ).fetchall()

    help_rows = db.execute(
        """
        SELECT
            h.*,
            p.firstName || ' ' || p.lastName AS personName
        FROM HelpRequest h
        JOIN Person p ON p.personID = h.personID
        ORDER BY
            CASE h.requestStatus
                WHEN 'Open' THEN 1
                WHEN 'In Progress' THEN 2
                ELSE 3
            END,
            h.createdAt DESC
        """
    ).fetchall()

    return render_template(
        "employee/dashboard.html",
        active_loans=active_loans,
        unpaid_fines=unpaid_fines,
        donations=donations,
        donated_by_donation=donated_by_donation,
        acquisitions=acquisitions,
        events=event_rows,
        copies=copies,
        help_requests=help_rows,
    )
    
@app.route("/employee/manage")
@employeeRequired("Event Coordinator", "Librarian", "Manager")
def managementPage():
    db = get_db()

    waiting_people = db.execute(
        """
        SELECT
            p.personID,
            p.firstName,
            p.lastName,
            p.email,
            p.phoneNumber,
            p.dateOfBirth
        FROM Person p
        JOIN Auth a ON a.personID = p.personID
        LEFT JOIN Member m ON m.personID = p.personID
        WHERE a.accountRole = 'User'
          AND m.memberID IS NULL
        ORDER BY p.firstName, p.lastName
        """
    ).fetchall()

    member_rows = db.execute(
        """
        SELECT
            m.memberID,
            m.membershipDate,
            m.membershipStatus,
            p.personID,
            p.firstName,
            p.lastName,
            p.email
        FROM Member m
        JOIN Person p ON p.personID = m.personID
        ORDER BY p.firstName, p.lastName
        """
    ).fetchall()

    volunteer_rows = db.execute(
        """
        SELECT
            va.assignmentID,
            va.role,
            va.status,
            va.numberOfHours,
            p.firstName || ' ' || p.lastName AS personName,
            e.eventName,
            e.eventDate
        FROM VolunteerAssignment va
        JOIN Person p ON p.personID = va.personID
        JOIN Event e ON e.eventID = va.eventID
        ORDER BY
            CASE va.status
                WHEN 'Pending' THEN 1
                WHEN 'Approved' THEN 2
                WHEN 'Completed' THEN 3
                ELSE 4
            END,
            e.eventDate,
            p.firstName
        """
    ).fetchall()

    registration_rows = db.execute(
        """
        SELECT
            er.registrationID,
            er.registrationDate,
            er.registrationStatus,
            p.firstName || ' ' || p.lastName AS personName,
            e.eventName,
            e.eventDate
        FROM EventRegistration er
        JOIN Person p ON p.personID = er.personID
        JOIN Event e ON e.eventID = er.eventID
        ORDER BY e.eventDate DESC, p.firstName
        """
    ).fetchall()

    event_rows = db.execute(
        """
        SELECT
            eventID,
            eventName,
            eventDate,
            eventStatus
        FROM Event
        ORDER BY eventDate, eventName
        """
    ).fetchall()

    audience_rows = db.execute(
        """
        SELECT audienceID, audienceName
        FROM Audience
        ORDER BY audienceName
        """
    ).fetchall()

    interest_rows = db.execute(
        """
        SELECT interestID, interestName
        FROM Interest
        ORDER BY interestName
        """
    ).fetchall()

    assigned_audiences = {}

    for row in db.execute(
        """
        SELECT
            ea.eventID,
            a.audienceID,
            a.audienceName
        FROM EventAudience ea
        JOIN Audience a ON a.audienceID = ea.audienceID
        ORDER BY a.audienceName
        """
    ).fetchall():
        assigned_audiences.setdefault(
            row["eventID"],
            [],
        ).append(row)

    assigned_interests = {}

    for row in db.execute(
        """
        SELECT
            ei.eventID,
            i.interestID,
            i.interestName
        FROM EventInterest ei
        JOIN Interest i ON i.interestID = ei.interestID
        ORDER BY i.interestName
        """
    ).fetchall():
        assigned_interests.setdefault(
            row["eventID"],
            [],
        ).append(row)

    return render_template(
        "employee/manage.html",
        waiting_people=waiting_people,
        members=member_rows,
        volunteers=volunteer_rows,
        registrations=registration_rows,
        events=event_rows,
        audiences=audience_rows,
        interests=interest_rows,
        assigned_audiences=assigned_audiences,
        assigned_interests=assigned_interests,
    )


@app.post("/employee/members/create/<int:person_id>")
@employeeRequired("Librarian", "Manager")
def createMember(person_id):
    db = get_db()

    person = db.execute(
        """
        SELECT p.personID
        FROM Person p
        JOIN Auth a ON a.personID = p.personID
        LEFT JOIN Member m ON m.personID = p.personID
        WHERE p.personID = ?
          AND a.accountRole = 'User'
          AND m.memberID IS NULL
        """,
        (person_id,),
    ).fetchone()

    if person is None:
        flash("Person does not exist or already has membership", "error")
        return redirect(url_for("managementPage"))

    try:
        with db:
            cursor = db.execute(
                """
                INSERT INTO Member
                (
                    personID,
                    membershipDate,
                    membershipStatus
                )
                VALUES (?, ?, 'Active')
                """,
                (
                    person_id,
                    currentDate(),
                ),
            )

        flash(f"Membership {cursor.lastrowid} is created", "success")

    except sqlite3.IntegrityError as error:
        flash(db_error(error), "error")

    return redirect(url_for("managementPage"))


@app.post("/employee/members/<int:member_id>/status")
@employeeRequired("Librarian", "Manager")
def changeMembership(member_id):
    status = request.form.get("status", "")

    if status not in ("Active", "Inactive", "Suspended"):
        abort(400)

    db = get_db()

    try:
        with db:
            cursor = db.execute(
                """
                UPDATE Member
                SET membershipStatus = ?
                WHERE memberID = ?
                """,
                (
                    status,
                    member_id,
                ),
            )

            if cursor.rowcount != 1:
                abort(404)

        flash(f"Membership status changed to {status}", "success")

    except sqlite3.IntegrityError as error:
        flash(db_error(error), "error")

    return redirect(url_for("managementPage"))


@app.post("/employee/volunteers/<int:assignment_id>")
@employeeRequired("Event Coordinator", "Librarian", "Manager")
def updateVolunteer(assignment_id):
    new_status = request.form.get("status", "")

    try:
        hours = float(
            request.form.get("number_of_hours", "0") or "0"
        )
    except ValueError:
        flash("Volunteer hours must be a number", "error")
        return redirect(url_for("managementPage"))

    if hours < 0:
        flash("Volunteer hours cannot be negative", "error")
        return redirect(url_for("managementPage"))

    db = get_db()

    assignment = db.execute(
        """
        SELECT status
        FROM VolunteerAssignment
        WHERE assignmentID = ?
        """,
        (assignment_id,),
    ).fetchone()

    if assignment is None:
        abort(404)

    allowed_changes = {
        "Pending": {
            "Approved",
            "Rejected",
        },
        "Approved": {
            "Completed",
            "Rejected",
        },
    }

    allowed_statuses = allowed_changes.get(
        assignment["status"],
        set(),
    )

    if new_status not in allowed_statuses:
        flash("This volunteer status change is not allowed", "error")
        return redirect(url_for("managementPage"))

    if new_status == "Completed" and hours <= 0:
        flash("Enter volunteer hours before marking completed", "error")
        return redirect(url_for("managementPage"))

    if new_status != "Completed":
        hours = 0

    try:
        with db:
            cursor = db.execute(
                """
                UPDATE VolunteerAssignment
                SET status = ?,
                    numberOfHours = ?
                WHERE assignmentID = ?
                """,
                (
                    new_status,
                    hours,
                    assignment_id,
                ),
            )

            if cursor.rowcount != 1:
                abort(404)

        flash(f"Volunteer application changed to {new_status}", "success")

    except sqlite3.IntegrityError as error:
        flash(db_error(error), "error")

    return redirect(url_for("managementPage"))


@app.post("/employee/registrations/<int:registration_id>/<action>")
@employeeRequired("Event Coordinator", "Librarian", "Manager")
def updateRegistration(registration_id, action):
    status_values = {
        "cancel": "Cancelled",
        "attended": "Attended",
        "no-show": "No-show",
    }

    if action not in status_values:
        abort(400)

    new_status = status_values[action]
    db = get_db()

    try:
        with db:
            cursor = db.execute(
                """
                UPDATE EventRegistration
                SET registrationStatus = ?
                WHERE registrationID = ?
                  AND registrationStatus = 'Registered'
                """,
                (
                    new_status,
                    registration_id,
                ),
            )

            if cursor.rowcount != 1:
                flash("Only a registered attendance can be changed", "error")
            else:
                flash(f"Registration changed to {new_status}", "success")

    except sqlite3.IntegrityError as error:
        flash(db_error(error), "error")

    return redirect(url_for("managementPage"))


@app.post("/employee/events/<int:event_id>/audiences")
@employeeRequired("Event Coordinator", "Librarian", "Manager")
def addEventAudience(event_id):
    try:
        audience_id = int(
            request.form.get("audience_id", "0")
        )
    except ValueError:
        abort(400)

    try:
        with get_db():
            get_db().execute(
                """
                INSERT INTO EventAudience
                (
                    eventID,
                    audienceID
                )
                VALUES (?, ?)
                """,
                (
                    event_id,
                    audience_id,
                ),
            )

        flash("Audience is assigned to event", "success")

    except sqlite3.IntegrityError as error:
        flash(db_error(error), "error")

    return redirect(url_for("managementPage"))


@app.post("/employee/events/<int:event_id>/audiences/<int:audience_id>/remove")
@employeeRequired("Event Coordinator", "Librarian", "Manager")
def removeEventAudience(event_id, audience_id):
    with get_db():
        cursor = get_db().execute(
            """
            DELETE FROM EventAudience
            WHERE eventID = ?
              AND audienceID = ?
            """,
            (
                event_id,
                audience_id,
            ),
        )

    if cursor.rowcount == 1:
        flash("Audience is removed from event", "success")
    else:
        flash("Audience assignment was not found", "error")

    return redirect(url_for("managementPage"))


@app.post("/employee/events/<int:event_id>/interests")
@employeeRequired("Event Coordinator", "Librarian", "Manager")
def addEventInterest(event_id):
    try:
        interest_id = int(
            request.form.get("interest_id", "0")
        )
    except ValueError:
        abort(400)

    try:
        with get_db():
            get_db().execute(
                """
                INSERT INTO EventInterest
                (
                    eventID,
                    interestID
                )
                VALUES (?, ?)
                """,
                (
                    event_id,
                    interest_id,
                ),
            )

        flash("Interest is assigned to event", "success")

    except sqlite3.IntegrityError as error:
        flash(db_error(error), "error")

    return redirect(url_for("managementPage"))


@app.post("/employee/events/<int:event_id>/interests/<int:interest_id>/remove")
@employeeRequired("Event Coordinator", "Librarian", "Manager")
def removeEventInterest(event_id, interest_id):
    with get_db():
        cursor = get_db().execute(
            """
            DELETE FROM EventInterest
            WHERE eventID = ?
              AND interestID = ?
            """,
            (
                event_id,
                interest_id,
            ),
        )

    if cursor.rowcount == 1:
        flash("Interest is removed from event", "success")
    else:
        flash("Interest assignment was not found", "error")

    return redirect(url_for("managementPage"))

@app.post("/employee/loans/<int:loan_id>/return")
@employeeRequired("Librarian", "Library Assistant", "Manager")
def employeeReturn(loan_id):
    try:
        with get_db():
            cursor = get_db().execute(
                """
                UPDATE Loan
                SET returnDateTime = ?
                WHERE loanID = ?
                  AND returnDateTime IS NULL
                """,
                (currentTime(), loan_id),
            )

            if cursor.rowcount != 1:
                abort(404)

        flash("Item is returned", "success")

    except sqlite3.IntegrityError as error:
        flash(db_error(error), "error")

    return redirect(url_for("employee_Dashboard"))


@app.post("/employee/fines/<int:fine_id>/<action>")
@employeeRequired("Librarian", "Manager")
def updateFine(fine_id, action):
    if action not in ("paid", "waived"):
        abort(400)

    status = "Paid" if action == "paid" else "Waived"
    payment_date = currentDate() if status == "Paid" else None

    try:
        with get_db():
            cursor = get_db().execute(
                """
                UPDATE Fine
                SET paymentStatus = ?,
                    paymentDate = ?
                WHERE fineID = ?
                  AND paymentStatus = 'Unpaid'
                """,
                (
                    status,
                    payment_date,
                    fine_id,
                ),
            )

            if cursor.rowcount != 1:
                flash("Only an unpaid fine can be changed", "error")
            else:
                flash(f"Fine marked as {status}", "success")

    except sqlite3.IntegrityError as error:
        flash(db_error(error), "error")

    return redirect(url_for("employee_Dashboard"))

@app.post("/employee/donated-items/<int:item_id>/<status>")
@employeeRequired("Librarian", "Manager")
def reviewDonatedItem(item_id, status):
    status_values = {
        "approve": "Approved",
        "reject": "Rejected",
        "pending": "Pending",
    }

    if status not in status_values:
        abort(400)

    db = get_db()

    item = db.execute(
        """
        SELECT
            di.donationID,
            d.donationStatus
        FROM DonatedItems di
        JOIN Donation d ON d.donationID = di.donationID
        WHERE di.donatedItemID = ?
        """,
        (item_id,),
    ).fetchone()

    if item is None:
        abort(404)

    if item["donationStatus"] != "Pending":
        flash("Completed donation cannot be reviewed again", "error")
        return redirect(url_for("employee_Dashboard"))

    try:
        with db:
            db.execute(
                """
                UPDATE DonatedItems
                SET approvalStatus = ?
                WHERE donatedItemID = ?
                """,
                (
                    status_values[status],
                    item_id,
                ),
            )

            db.execute(
                """
                UPDATE Donation
                SET reviewEmployeeID = ?
                WHERE donationID = ?
                """,
                (
                    g.employee["employeeID"],
                    item["donationID"],
                ),
            )

        flash("Donated item review is updated", "success")

    except sqlite3.IntegrityError as error:
        flash(db_error(error), "error")

    return redirect(url_for("employee_Dashboard"))


@app.post("/employee/donations/<int:donation_id>/<status>")
@employeeRequired("Librarian", "Manager")
def finalDonation(donation_id, status):
    if status not in ("Approved", "Rejected"):
        abort(400)

    try:
        with get_db():
            cursor = get_db().execute(
                """
                UPDATE Donation
                SET donationStatus = ?,
                    reviewEmployeeID = ?
                WHERE donationID = ?
                  AND donationStatus = 'Pending'
                """,
                (
                    status,
                    g.employee["employeeID"],
                    donation_id,
                ),
            )

            if cursor.rowcount != 1:
                flash("Donation is already completed", "error")
            else:
                flash(f"Donation marked as {status}", "success")

    except sqlite3.IntegrityError as error:
        flash(db_error(error), "error")

    return redirect(url_for("employee_Dashboard"))

@app.post("/employee/acquisitions/<int:acquisition_id>/<status>")
@employeeRequired("Librarian", "Manager")
def reviewAcquisition(acquisition_id, status):
    status_values = {
        "review": "Under Review",
        "approve": "Approved",
        "reject": "Rejected",
    }

    if status not in status_values:
        abort(400)
        
    db = get_db()

    try:
        with db:
            cursor = db.execute(
                """
                UPDATE FutureAcquisitions
                SET requestStatus = ?,
                    employeeID = ?
                WHERE acquisitionID = ?
                    AND requestStatus <> 'Acquired'
                """,
                (
                    status_values[status],
                    g.employee["employeeID"],
                    acquisition_id,
                ),
            )
            
            if cursor.rowcount != 1:
                abort(404)

        flash("Acquisition request is updated", "success")

    except sqlite3.IntegrityError as error:
        flash(db_error(error), "error")

    return redirect(url_for("employee_Dashboard"))

@app.route(
    "/employee/import/<source_type>/<int:source_id>",
    methods=("GET", "POST"),
)
@employeeRequired("Librarian", "Manager")
def collectionImport(source_type, source_id):
    if source_type not in ("donation", "acquisition"):
        abort(404)

    db = get_db()

    if source_type == "donation":
        source = db.execute(
            """
            SELECT
                di.donatedItemID AS sourceID,
                di.title,
                di.itemType,
                di.author,
                di.quantity,
                di.itemCondition,
                di.approvalStatus,
                d.donationStatus
            FROM DonatedItems di
            JOIN Donation d ON d.donationID = di.donationID
            WHERE di.donatedItemID = ?
            """,
            (source_id,),
        ).fetchone()

        allowed = (
            source is not None
            and source["donationStatus"] == "Approved"
            and source["approvalStatus"] == "Approved"
        )

        quantity = source["quantity"] if source else 0
        final_source_type = "Donation"

    else:
        source = db.execute(
            """
            SELECT
                acquisitionID AS sourceID,
                title,
                itemType,
                author,
                proposedQuantity AS quantity,
                requestStatus
            FROM FutureAcquisitions
            WHERE acquisitionID = ?
            """,
            (source_id,),
        ).fetchone()

        allowed = (
            source is not None
            and source["requestStatus"] == "Approved"
        )

        quantity = source["quantity"] if source else 0
        final_source_type = "Acquisition"

    if source is None:
        abort(404)

    if not allowed:
        flash("This item is not approved for collection import", "error")
        return redirect(url_for("employee_Dashboard"))

    old_import = db.execute(
        """
        SELECT libraryItemID
        FROM AddCollection
        WHERE sourceType = ?
          AND sourceID = ?
        """,
        (
            final_source_type,
            source_id,
        ),
    ).fetchone()

    if old_import:
        flash(
            f"This item is already added as LibraryItem "
            f"{old_import['libraryItemID']}",
            "error",
        )
        return redirect(url_for("employee_Dashboard"))

    if request.method == "POST":
        item_type = request.form.get("item_type", "")
        publisher = request.form.get("publisher", "").strip() or None
        language = request.form.get("language", "").strip() or None
        isbn = request.form.get("isbn", "").strip() or None
        online_url = request.form.get("online_url", "").strip() or None
        shelf = request.form.get("shelf_location", "").strip() or None
        condition = request.form.get("condition", "Good")

        year_value = request.form.get(
            "publication_year",
            "",
        ).strip()

        try:
            publication_year = (
                int(year_value)
                if year_value
                else None
            )
        except ValueError:
            flash("Publication year must be a number", "error")
            return render_template(
                "employee/importItem.html",
                source=source,
                source_type=source_type,
                quantity=quantity,
            )

        barcode_lines = request.form.get(
            "barcodes",
            "",
        ).splitlines()

        barcodes = [
            barcode.strip()
            for barcode in barcode_lines
            if barcode.strip()
        ]

        if item_type not in LIBRARY_ITEM_TYPES:
            flash("Select valid item type", "error")

        elif item_type == "Online Book" and not online_url:
            flash("Online books need access URL", "error")

        elif item_type == "Online Book" and barcodes:
            flash("Online books cannot have barcodes", "error")

        elif item_type != "Online Book" and len(barcodes) != quantity:
            flash(
                f"Enter exactly {quantity} barcodes, one per line",
                "error",
            )

        elif len(barcodes) != len(set(barcodes)):
            flash("Barcodes must be unique", "error")

        else:
            try:
                with db:
                    cursor = db.execute(
                        """
                        INSERT INTO LibraryItem
                        (
                            itemTitle,
                            itemType,
                            author,
                            publisher,
                            publicationYear,
                            language,
                            ISBN,
                            onlineAccessURL
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            source["title"],
                            item_type,
                            source["author"],
                            publisher,
                            publication_year,
                            language,
                            isbn,
                            online_url,
                        ),
                    )

                    library_item_id = cursor.lastrowid

                    for barcode in barcodes:
                        db.execute(
                            """
                            INSERT INTO BorrowableItem
                            (
                                itemID,
                                barcode,
                                shelfLocation,
                                itemCondition,
                                itemStatus
                            )
                            VALUES (?, ?, ?, ?, 'Available')
                            """,
                            (
                                library_item_id,
                                barcode,
                                shelf,
                                condition,
                            ),
                        )

                    db.execute(
                        """
                        INSERT INTO AddCollection
                        (
                            sourceType,
                            sourceID,
                            libraryItemID,
                            processEmployeeID,
                            processAt
                        )
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            final_source_type,
                            source_id,
                            library_item_id,
                            g.employee["employeeID"],
                            currentTime(),
                        ),
                    )

                flash(
                    f"LibraryItem {library_item_id} is created",
                    "success",
                )

                return redirect(url_for("employee_Dashboard"))

            except sqlite3.IntegrityError as error:
                flash(db_error(error), "error")

    return render_template(
        "employee/importItem.html",
        source=source,
        source_type=source_type,
        quantity=quantity,
    )
    
@app.route("/employee/events/new", methods=("GET", "POST"))
@employeeRequired("Event Coordinator", "Librarian", "Manager")
def newEvent():
    rooms = get_db().execute(
        """
        SELECT *
        FROM Room
        ORDER BY roomName
        """
    ).fetchall()

    if request.method == "POST":
        final_status = request.form.get("event_status", "Closed")

        if final_status not in ("Open", "Closed", "Cancelled"):
            abort(400)

        try:
            room_id = int(request.form.get("room_id", "0"))
            capacity = int(request.form.get("capacity", "0"))

            with get_db():
                cursor = get_db().execute(
                    """
                    INSERT INTO Event
                    (
                        eventName,
                        eventType,
                        description,
                        eventDate,
                        startTime,
                        endTime,
                        roomID,
                        eventCapacity,
                        eventStatus
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Closed')
                    """,
                    (
                        request.form.get("event_name", "").strip(),
                        request.form.get("event_type", ""),
                        request.form.get("description", "").strip() or None,
                        request.form.get("event_date", ""),
                        request.form.get("start_time", ""),
                        request.form.get("end_time", ""),
                        room_id,
                        capacity,
                    ),
                )

                event_id = cursor.lastrowid

                get_db().execute(
                    """
                    INSERT INTO OrganizedBy(employeeID, eventID)
                    VALUES (?, ?)
                    """,
                    (
                        g.employee["employeeID"],
                        event_id,
                    ),
                )

                if final_status != "Closed":
                    get_db().execute(
                        """
                        UPDATE Event
                        SET eventStatus = ?
                        WHERE eventID = ?
                        """,
                        (
                            final_status,
                            event_id,
                        ),
                    )

            flash("Event is created", "success")
            return redirect(url_for("employee_Dashboard"))

        except (sqlite3.IntegrityError, ValueError) as error:
            flash(db_error(error), "error")

    return render_template(
        "employee/eventForm.html",
        rooms=rooms,
    )


@app.post("/employee/events/<int:event_id>/status")
@employeeRequired("Event Coordinator", "Librarian", "Manager")
def changeEventStatus(event_id):
    status = request.form.get("status", "")

    if status not in ("Open", "Closed", "Cancelled"):
        abort(400)
        
    db = get_db()

    try:
        with db:
            cursor = db.execute(
                """
                UPDATE Event
                SET eventStatus = ?
                WHERE eventID = ?
                """,
                (
                    status,
                    event_id,
                ),
            )
            
            if cursor.rowcount != 1:
                abort(404)

        flash(f"Event status changed to {status}", "success")

    except sqlite3.IntegrityError as error:
        flash(db_error(error), "error")

    return redirect(url_for("employee_Dashboard"))


@app.post("/employee/copies/<int:copy_id>")
@employeeRequired("Technician", "Librarian", "Manager")
def updateCopy(copy_id):
    condition = request.form.get("condition", "")
    status = request.form.get("status", "")

    if condition not in ("New", "Good", "Fair", "Damaged"):
        abort(400)

    # Borrowed must only be controlled by Loan triggers.
    if status not in ("Available", "Lost", "Maintenance"):
        abort(400)

    active_loan = get_db().execute(
        """
        SELECT loanID
        FROM Loan
        WHERE borrowableItemID = ?
          AND returnDateTime IS NULL
        """,
        (copy_id,),
    ).fetchone()

    if active_loan:
        flash("A borrowed copy cannot be manually changed", "error")
        return redirect(url_for("employee_Dashboard"))

    try:
        db = get_db()
        with db:
            cursor = db.execute(
                """
                UPDATE BorrowableItem
                SET itemCondition = ?,
                    itemStatus = ?
                WHERE borrowableItemID = ?
                """,
                (
                    condition,
                    status,
                    copy_id,
                ),
            )
            
            if cursor.rowcount != 1:
                abort(404)

        flash("Physical copy is updated", "success")

    except sqlite3.IntegrityError as error:
        flash(db_error(error), "error")

    return redirect(url_for("employee_Dashboard"))

@app.post("/employee/help/<int:help_id>")
@employeeRequired("Librarian", "Manager")
def answerHelp(help_id):
    response = request.form.get("response", "").strip()
    status = request.form.get("status", "In Progress")

    if status not in ("In Progress", "Resolved"):
        abort(400)

    if not response:
        flash("Enter response first", "error")
        return redirect(url_for("employee_Dashboard"))

    resolved_at = (
        currentTime()
        if status == "Resolved"
        else None
    )
    
    db = get_db()

    with db:
        cursor = db.execute(
            """
            UPDATE HelpRequest
            SET assignedEmployeeID = ?,
                response = ?,
                requestStatus = ?,
                resolvedAt = ?
            WHERE helpRequestID = ?
            """,
            (
                g.employee["employeeID"],
                response,
                status,
                resolved_at,
                help_id,
            ),
        )
        
        if cursor.rowcount != 1:
            abort(404)

    flash("Help request is updated", "success")
    return redirect(url_for("employee_Dashboard"))

@app.cli.command("create-employee")
@click.argument("employee_id", type=int)
def createEmployee(employee_id):

    with app.app_context():
        employee = get_db().execute(
            """
            SELECT
                e.employeeID,
                e.personID,
                p.firstName,
                p.lastName,
                p.email
            FROM Employee e
            JOIN Person p ON p.personID = e.personID
            WHERE e.employeeID = ?
            """,
            (employee_id,),
        ).fetchone()

        if employee is None:
            raise click.ClickException("Employee does not exist")

        password = getpass("Password: ")
        confirmation = getpass("Confirm password: ")

        if len(password) < 10:
            raise click.ClickException(
                "Password must have at least 10 characters"
            )

        if password != confirmation:
            raise click.ClickException("Passwords do not match")

        try:
            with get_db():
                get_db().execute(
                    """
                    INSERT INTO Auth
                    (
                        personID,
                        passwordHash,
                        accountRole,
                        createdAt
                    )
                    VALUES (?, ?, 'Employee', ?)
                    """,
                    (
                        employee["personID"],
                        generate_password_hash(password, method="pbkdf2:sha256"),
                        currentTime(),
                    ),
                )

        except sqlite3.IntegrityError as error:
            raise click.ClickException(
                db_error(error)
            ) from error

        click.echo(
            f"Employee login created for "
            f"{employee['firstName']} {employee['lastName']} "
            f"using {employee['email']}"
        )



if __name__ == "__main__":
    app.run(
        debug=os.getenv("FLASK_DEBUG") == "1"
    )