"""

1. Blockchain persistent (restart safe)
2. Private key stored in session, not in DB
3. Admin can add/remove candidates
4. Admin panel with blockchain test
5. AES key persistent
"""
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from blockchain import Blockchain
from auth import (
    init_db, register_voter, login_voter, get_candidates, get_voter,
    get_audit_log, log_action, verify_admin, verify_admin_key, ADMIN_SECRET_KEY,
    add_candidate, remove_candidate, get_candidates_full
)
from vote import cast_vote, get_voter_receipt, verify_vote_signature
from results import get_results, get_winner, get_total_votes, verify_chain, get_chain_data, verify_all_signatures, generate_audit_report
import json
from time import time

app = Flask(__name__)
app.secret_key = "blockvote_advanced_2024"

blockchain = Blockchain(
    election_start = time() - 1,
    election_end   = time() + (365 * 24 * 3600)
)

init_db()


@app.route("/")
def index():
    total = get_total_votes(blockchain)
    winner = get_winner(blockchain)
    time_status = blockchain.get_time_status()
    return render_template("index.html", total=total, winner=winner, time_status=time_status)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        national_id = request.form.get("national_id", "").strip()
        password = request.form.get("password", "").strip()
        if not name or not national_id or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html")

        success, result, private_key = register_voter(name, national_id, password)
        if success:
            #Store private key in session, not in DB
            session["voter_private_key"] = private_key
            flash(f"Registration successful! Your Voter ID: {result}", "success")
            return render_template("register.html", voter_id=result, private_key_hint=True)
        else:
            flash(result, "danger")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "voter_id" in session:
        return redirect(url_for("vote"))
    if request.method == "POST":
        voter_id = request.form.get("voter_id", "").strip().upper()
        password = request.form.get("password", "").strip()
        ip = request.remote_addr
        voter, message = login_voter(voter_id, password, ip)
        if voter:
            session["voter_id"] = voter["voter_id"]
            session["voter_name"] = voter["name"]
            #  Private key is not available on login (security by design)
            # If no private key on vote page, voter must re-register
            flash(f"Welcome, {voter['name']}!", "success")
            return redirect(url_for("vote"))
        else:
            flash(message, "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    voter_id = session.get("voter_id")
    if voter_id:
        log_action(voter_id, "LOGOUT", "User logged out")
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("index"))


@app.route("/vote", methods=["GET", "POST"])
def vote():
    if "voter_id" not in session:
        flash("Please log in to vote.", "warning")
        return redirect(url_for("login"))

    voter_id = session["voter_id"]
    voter = get_voter(voter_id)

    if voter and voter["has_voted"]:
        receipt = get_voter_receipt(blockchain, voter_id)
        sig_check = verify_vote_signature(blockchain, voter_id)
        return render_template("already_voted.html", receipt=receipt, sig_check=sig_check)

    if request.method == "POST":
        candidate = request.form.get("candidate", "")
        # Get private key from session
        private_key_pem = session.get("voter_private_key")
        success, message = cast_vote(blockchain, voter_id, candidate, private_key_pem)
        if success:
            # Remove private key from session after use (one-time use)
            session.pop("voter_private_key", None)
            flash(message, "success")
            return redirect(url_for("receipt"))
        else:
            flash(message, "danger")

    time_status = blockchain.get_time_status()
    has_key = "voter_private_key" in session
    return render_template("vote.html",
                           candidates=get_candidates(),
                           voter_name=session.get("voter_name"),
                           time_status=time_status,
                           has_signing_key=has_key)


@app.route("/receipt")
def receipt():
    if "voter_id" not in session:
        return redirect(url_for("login"))
    voter_id = session["voter_id"]
    receipt = get_voter_receipt(blockchain, voter_id)
    sig_check = verify_vote_signature(blockchain, voter_id)
    return render_template("receipt.html", receipt=receipt, sig_check=sig_check)


@app.route("/results")
def results():
    results_data = get_results(blockchain)
    winner = get_winner(blockchain)
    total = get_total_votes(blockchain)
    return render_template("results.html", results=results_data, winner=winner, total=total)


@app.route("/api/results")
def api_results():
    return {
        "results": get_results(blockchain),
        "total": get_total_votes(blockchain),
        "winner": get_winner(blockchain)
    }


# ─── Admin Panel ──────────────────────────────────────────────────────────────

@app.route("/admin", methods=["GET", "POST"])
def admin():
    key = request.args.get("key", "")
    if not verify_admin_key(key):
        log_action("unknown", "ADMIN_ACCESS_DENIED", f"Wrong key from {request.remote_addr}")
        return render_template("admin_login.html", error="Invalid secret key. Access denied."), 403

    if not session.get("is_admin"):
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            secret_key = request.form.get("secret_key", "")
            if not verify_admin_key(secret_key):
                flash("Invalid secret key.", "danger")
                return render_template("admin_login.html")
            if verify_admin(username, password):
                session["is_admin"] = True
                session["admin_name"] = username
                log_action(username, "ADMIN_LOGIN_SUCCESS", f"Admin logged in from {request.remote_addr}")
                flash("Admin access granted.", "success")
            else:
                log_action(username, "ADMIN_LOGIN_FAIL", f"Wrong credentials from {request.remote_addr}")
                flash("Invalid admin credentials.", "danger")
                return render_template("admin_login.html")
        else:
            return render_template("admin_login.html")

    audit = verify_chain(blockchain)
    chain_data = get_chain_data(blockchain)
    sig_results = verify_all_signatures(blockchain)
    audit_log = get_audit_log(30)
    candidates = get_candidates_full()
    return render_template("admin.html",
                           audit=audit,
                           chain=chain_data,
                           sig_results=sig_results,
                           audit_log=audit_log,
                           admin_key=ADMIN_SECRET_KEY,
                           candidates=candidates,
                           blockchain_blocks=len(blockchain.chain),
                           total_votes=get_total_votes(blockchain))


@app.route("/admin/add-candidate", methods=["POST"])
def admin_add_candidate():
    if not session.get("is_admin"):
        return redirect(url_for("admin"))
    name = request.form.get("candidate_name", "").strip()
    party = request.form.get("candidate_party", "").strip()
    success, msg = add_candidate(name, party)
    if success:
        flash(msg, "success")
        log_action(session.get("admin_name", "admin"), "CANDIDATE_ADDED", f"Added: {name} ({party})")
    else:
        flash(msg, "danger")
    return redirect(url_for("admin", key=ADMIN_SECRET_KEY))


@app.route("/admin/remove-candidate/<int:cid>", methods=["POST"])
def admin_remove_candidate(cid):
    if not session.get("is_admin"):
        return redirect(url_for("admin"))
    success, msg = remove_candidate(cid)
    flash(msg, "success" if success else "danger")
    log_action(session.get("admin_name", "admin"), "CANDIDATE_REMOVED", f"Removed ID: {cid}")
    return redirect(url_for("admin", key=ADMIN_SECRET_KEY))


@app.route("/admin/test-blockchain")
def admin_test_blockchain():
    """Blockchain integrity test + summary."""
    if not session.get("is_admin"):
        return redirect(url_for("admin"))
    audit = verify_chain(blockchain)
    sig_results = verify_all_signatures(blockchain)
    all_sigs_valid = all(r["signature_valid"] for r in sig_results)
    return {
        "chain_valid": audit["is_valid"],
        "total_blocks": audit["total_blocks"],
        "total_votes": get_total_votes(blockchain),
        "all_signatures_valid": all_sigs_valid,
        "signature_count": len(sig_results),
        "blocks": audit["blocks"],
        "message": "✓ Blockchain and signatures are valid" if (audit["is_valid"] and all_sigs_valid)
                   else "⚠ Some issues found — check details"
    }


@app.route("/admin/logout")
def admin_logout():
    log_action(session.get("admin_name", "admin"), "ADMIN_LOGOUT", "Admin logged out")
    session.pop("is_admin", None)
    session.pop("admin_name", None)
    flash("Admin logged out successfully.", "info")
    return redirect(url_for("index"))


@app.route("/admin/download-report")
def download_report():
    if not session.get("is_admin"):
        return redirect(url_for("admin"))
    report = generate_audit_report(blockchain)
    log_action(session.get("admin_name", "admin"), "REPORT_DOWNLOADED", "Audit report downloaded")
    return Response(
        report,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=election_audit_report.txt"}
    )


if __name__ == "__main__":
    app.run(debug=True)
