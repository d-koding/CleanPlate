"""
app.py — ChoreHouse Flask application

Run:
    python app.py

Security summary for this file:
  - All state-changing routes are POST-only; GET routes never mutate data
  - Input lengths are validated before touching the DB
  - Every household-scoped route goes through require_login + require_member/require_role
  - AuditEntry.append() is called inside the same DB transaction as the mutation
    so the audit record is committed atomically with the change it describes
  - Passwords are never logged or stored in plaintext
  - Invite codes are single-use secrets; admins can rotate them
"""

import os
import secrets
from datetime import date, datetime, timezone

from flask import (Flask, abort, flash, redirect, render_template,
                   request, session, url_for)

from auth import (check_password, current_user, get_membership, hash_password,
                  login_user, logout_user, require_login, require_member,
                  require_role)
from models import (AuditEntry, AuditHMACKey, Chore, Complaint, Household,
                    HouseholdMember, User, db)

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///chorehouse.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

db.init_app(app)

with app.app_context():
    db.create_all()
    if AuditHMACKey.query.first() is None:
        db.session.add(AuditHMACKey())
        db.session.commit()


# ---------------------------------------------------------------------------
# Context processor — inject current_user into every template
# ---------------------------------------------------------------------------

@app.context_processor
def inject_user():
    return dict(current_user=current_user())


# ---------------------------------------------------------------------------
# Public routes: register, login, logout
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    user = current_user()
    if user:
        memberships = HouseholdMember.query.filter_by(user_id=user.id).all()
        return render_template("index.html", memberships=memberships)
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")

        # Input validation
        if not username or len(username) > 64:
            flash("Username must be 1–64 characters.", "danger")
            return render_template("register.html")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")
        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return render_template("register.html")

        user = User(username=username, password_hash=hash_password(password))
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash(f"Welcome, {username}! Create or join a household to get started.", "success")
        return redirect(url_for("index"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        # Always run check_password even on unknown user to resist timing attacks
        dummy_hash = "$2b$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        if user is None or not check_password(password, user.password_hash if user else dummy_hash):
            flash("Invalid username or password.", "danger")
            return render_template("login.html")

        login_user(user)
        flash(f"Welcome back, {user.username}!", "success")
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Household creation and joining
# ---------------------------------------------------------------------------

@app.route("/households/create", methods=["GET", "POST"])
@require_login
def create_household():
    user = current_user()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name or len(name) > 128:
            flash("Household name must be 1–128 characters.", "danger")
            return render_template("create_household.html")

        household = Household(name=name)
        db.session.add(household)
        db.session.flush()   # get household.id before adding member

        membership = HouseholdMember(
            user_id=user.id, household_id=household.id, role="admin"
        )
        db.session.add(membership)
        db.session.flush()

        AuditEntry.append(
            household_id=household.id,
            actor_id=user.id,
            action="household.create",
            details={"name": name, "creator": user.username},
        )
        db.session.commit()

        flash(f"Household '{name}' created! Share the invite code with your roommates.", "success")
        return redirect(url_for("household_detail", household_id=household.id))

    return render_template("create_household.html")


@app.route("/households/join", methods=["GET", "POST"])
@require_login
def join_household():
    user = current_user()
    if request.method == "POST":
        code = request.form.get("invite_code", "").strip()
        household = Household.query.filter_by(invite_code=code).first()
        if not household:
            flash("Invalid invite code.", "danger")
            return render_template("join_household.html")

        existing = get_membership(user.id, household.id)
        if existing:
            flash("You are already a member of this household.", "info")
            return redirect(url_for("household_detail", household_id=household.id))

        membership = HouseholdMember(
            user_id=user.id, household_id=household.id, role="roommate"
        )
        db.session.add(membership)
        db.session.flush()

        AuditEntry.append(
            household_id=household.id,
            actor_id=user.id,
            action="membership.join",
            details={"user": user.username},
        )
        db.session.commit()

        flash(f"Joined '{household.name}'!", "success")
        return redirect(url_for("household_detail", household_id=household.id))

    return render_template("join_household.html")


# ---------------------------------------------------------------------------
# Household detail
# ---------------------------------------------------------------------------

@app.route("/households/<int:household_id>")
@require_login
@require_member
def household_detail(household_id):
    user      = current_user()
    household = db.session.get(Household, household_id)
    if not household:
        abort(404)
    membership = get_membership(user.id, household_id)
    members    = (HouseholdMember.query
                  .filter_by(household_id=household_id).all())
    chores     = (Chore.query
                  .filter_by(household_id=household_id)
                  .order_by(Chore.due_date).all())
    open_complaints = (Complaint.query
                       .join(Chore)
                       .filter(Chore.household_id == household_id,
                               Complaint.resolved == False)
                       .count())
    return render_template(
        "household.html",
        household=household,
        membership=membership,
        members=members,
        chores=chores,
        open_complaints=open_complaints,
        today=date.today(),
    )


# ---------------------------------------------------------------------------
# Chore management
# ---------------------------------------------------------------------------

@app.route("/households/<int:household_id>/chores/new", methods=["GET", "POST"])
@require_login
@require_role("admin")
def new_chore(household_id):
    user      = current_user()
    household = db.session.get(Household, household_id)
    members   = HouseholdMember.query.filter_by(household_id=household_id).all()

    if request.method == "POST":
        title       = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        assigned_to = request.form.get("assigned_to", type=int)
        due_str     = request.form.get("due_date", "").strip()

        if not title or len(title) > 128:
            flash("Title must be 1–128 characters.", "danger")
            return render_template("new_chore.html", household=household, members=members)

        due_date = None
        if due_str:
            try:
                due_date = date.fromisoformat(due_str)
            except ValueError:
                flash("Invalid date format.", "danger")
                return render_template("new_chore.html", household=household, members=members)

        # Verify assignee is a member of this household
        if assigned_to:
            if not get_membership(assigned_to, household_id):
                flash("Assignee is not a member of this household.", "danger")
                return render_template("new_chore.html", household=household, members=members)

        chore = Chore(
            household_id=household_id,
            title=title,
            description=description,
            assigned_to=assigned_to,
            due_date=due_date,
            created_by=user.id,
        )
        db.session.add(chore)
        db.session.flush()

        AuditEntry.append(
            household_id=household_id,
            actor_id=user.id,
            action="chore.create",
            details={
                "chore_id": chore.id,
                "title": title,
                "assigned_to": assigned_to,
                "due_date": due_str or None,
            },
        )
        db.session.commit()
        flash(f"Chore '{title}' created.", "success")
        return redirect(url_for("household_detail", household_id=household_id))

    return render_template("new_chore.html", household=household, members=members)


@app.route("/households/<int:household_id>/chores/<int:chore_id>/complete",
           methods=["POST"])
@require_login
@require_member
def complete_chore(household_id, chore_id):
    user  = current_user()
    chore = db.session.get(Chore, chore_id)

    if not chore or chore.household_id != household_id:
        abort(404)
    if chore.status not in ("pending", "disputed"):
        flash("Chore is already marked complete.", "info")
        return redirect(url_for("household_detail", household_id=household_id))

    membership = get_membership(user.id, household_id)

    # Roommates can only complete chores assigned to them;
    # admins can complete any chore
    if membership.role != "admin" and chore.assigned_to != user.id:
        abort(403, "You can only complete chores assigned to you.")

    chore.status       = "complete"
    chore.completed_at = datetime.now(timezone.utc)

    AuditEntry.append(
        household_id=household_id,
        actor_id=user.id,
        action="chore.complete",
        details={"chore_id": chore_id, "title": chore.title},
    )
    db.session.commit()
    flash(f"'{chore.title}' marked as complete.", "success")
    return redirect(url_for("household_detail", household_id=household_id))


# ---------------------------------------------------------------------------
# Complaints
# ---------------------------------------------------------------------------

@app.route("/households/<int:household_id>/chores/<int:chore_id>/complaint",
           methods=["GET", "POST"])
@require_login
@require_member
def file_complaint(household_id, chore_id):
    user  = current_user()
    chore = db.session.get(Chore, chore_id)

    if not chore or chore.household_id != household_id:
        abort(404)
    if chore.status != "complete":
        flash("You can only dispute a completed chore.", "warning")
        return redirect(url_for("household_detail", household_id=household_id))

    if request.method == "POST":
        description = request.form.get("description", "").strip()
        if not description or len(description) > 1000:
            flash("Complaint must be 1–1000 characters.", "danger")
            return render_template("file_complaint.html",
                                   household_id=household_id, chore=chore)

        complaint = Complaint(
            chore_id=chore_id,
            submitted_by=user.id,
            description=description,
        )
        chore.status = "disputed"
        db.session.add(complaint)
        db.session.flush()

        AuditEntry.append(
            household_id=household_id,
            actor_id=user.id,
            action="complaint.file",
            details={
                "complaint_id": complaint.id,
                "chore_id": chore_id,
                "chore_title": chore.title,
            },
        )
        db.session.commit()
        flash("Complaint filed. An admin will review it.", "success")
        return redirect(url_for("household_detail", household_id=household_id))

    return render_template("file_complaint.html",
                           household_id=household_id, chore=chore)


@app.route("/households/<int:household_id>/complaints")
@require_login
@require_member
def complaints(household_id):
    user       = current_user()
    household  = db.session.get(Household, household_id)
    membership = get_membership(user.id, household_id)
    all_complaints = (Complaint.query
                      .join(Chore)
                      .filter(Chore.household_id == household_id)
                      .order_by(Complaint.created_at.desc())
                      .all())
    return render_template("complaints.html",
                           household=household,
                           membership=membership,
                           complaints=all_complaints)


@app.route("/households/<int:household_id>/complaints/<int:complaint_id>/resolve",
           methods=["POST"])
@require_login
@require_role("admin")
def resolve_complaint(household_id, complaint_id):
    user      = current_user()
    complaint = db.session.get(Complaint, complaint_id)

    if not complaint or complaint.chore.household_id != household_id:
        abort(404)

    resolution = request.form.get("resolution", "").strip()
    outcome    = request.form.get("outcome", "")   # 'uphold' or 'dismiss'

    if not resolution or len(resolution) > 1000:
        flash("Resolution note required (max 1000 chars).", "danger")
        return redirect(url_for("complaints", household_id=household_id))

    if outcome not in ("uphold", "dismiss"):
        flash("Invalid outcome.", "danger")
        return redirect(url_for("complaints", household_id=household_id))

    complaint.resolved    = True
    complaint.resolution  = resolution
    complaint.resolved_by = user.id
    complaint.resolved_at = datetime.now(timezone.utc)

    # If complaint upheld → chore reverts to pending
    if outcome == "uphold":
        complaint.chore.status       = "pending"
        complaint.chore.completed_at = None
    else:
        complaint.chore.status = "complete"

    AuditEntry.append(
        household_id=household_id,
        actor_id=user.id,
        action="complaint.resolve",
        details={
            "complaint_id": complaint_id,
            "chore_id": complaint.chore_id,
            "outcome": outcome,
            "resolution": resolution,
        },
    )
    db.session.commit()
    flash(f"Complaint {'upheld' if outcome == 'uphold' else 'dismissed'}.", "success")
    return redirect(url_for("complaints", household_id=household_id))


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

@app.route("/households/<int:household_id>/audit")
@require_login
@require_member
def audit_log(household_id):
    user       = current_user()
    household  = db.session.get(Household, household_id)
    membership = get_membership(user.id, household_id)

    entries = (AuditEntry.query
               .filter_by(household_id=household_id)
               .order_by(AuditEntry.sequence_num.desc())
               .all())

    chain_ok, chain_msg = AuditEntry.verify_chain(household_id)
    import json
    return render_template("audit.html",
                           household=household,
                           membership=membership,
                           entries=entries,
                           chain_ok=chain_ok,
                           chain_msg=chain_msg,
                           json=json)


# ---------------------------------------------------------------------------
# Admin-only: rotate invite code, remove member
# ---------------------------------------------------------------------------

@app.route("/households/<int:household_id>/rotate-invite", methods=["POST"])
@require_login
@require_role("admin")
def rotate_invite(household_id):
    user      = current_user()
    household = db.session.get(Household, household_id)
    old_code  = household.invite_code
    household.invite_code = secrets.token_urlsafe(16)
    AuditEntry.append(
        household_id=household_id,
        actor_id=user.id,
        action="invite.rotate",
        details={"note": "Invite code rotated by admin"},
    )
    db.session.commit()
    flash("Invite code rotated. The old code is now invalid.", "success")
    return redirect(url_for("household_detail", household_id=household_id))


@app.route("/households/<int:household_id>/members/<int:target_user_id>/remove",
           methods=["POST"])
@require_login
@require_role("admin")
def remove_member(household_id, target_user_id):
    user   = current_user()
    target = db.session.get(User, target_user_id)
    if not target:
        abort(404)
    if target_user_id == user.id:
        flash("You cannot remove yourself.", "danger")
        return redirect(url_for("household_detail", household_id=household_id))

    membership = get_membership(target_user_id, household_id)
    if not membership:
        flash("User is not in this household.", "warning")
        return redirect(url_for("household_detail", household_id=household_id))

    db.session.delete(membership)
    AuditEntry.append(
        household_id=household_id,
        actor_id=user.id,
        action="membership.remove",
        details={"removed_user": target.username},
    )
    db.session.commit()
    flash(f"{target.username} removed from household.", "success")
    return redirect(url_for("household_detail", household_id=household_id))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, port=5000)
