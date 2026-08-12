import io
import os
import sqlite3
from datetime import datetime
from pathlib import Path

import base64
import hashlib
import hmac
import secrets
import pandas as pd
import plotly.express as px
import streamlit as st


# ============================================================
# CCDATA – Attribut-, Pflichtenheft- und Kostenmonitor
# ============================================================

st.set_page_config(
    page_title="CCDATA | Projekt- & Kostenmonitor",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded",
)

COMPANY_NAME = "CCDATA"
APP_NAME = "Projekt- & Kostenmonitor"
DB_PATH = Path(os.getenv("CCDATA_DB_PATH", "ccdata.db"))

SOURCE_SHEETS = ["Unternehmen", "Trainer", "CCData Admin", "Teilnehmer"]
DEFAULT_RATE = 100.0

EDITABLE_COLUMNS = [
    "Kategorie",
    "Attribut",
    "Datendomäne",
    "Beschreibung / Inhalt",
    "Datentyp",
    "Pflichtgrad",
    "Herleitung",
    "Technische Feld-ID",
    "Freigabe/Kommentar",
    "Entscheidungsebene_Programmierung",
    "Entscheidungsebene_Controlling",
    "Entwicklungspriorität",
    "Komplexität",
    "Aufwand in Mannstunden",
    "Ressourcenrolle",
    "Status",
]

DEFAULT_ROLES = {
    "Geschäftsführung": 140.0,
    "Programmierung": 110.0,
    "Controlling": 95.0,
    "UX/UI": 95.0,
    "Testing/QA": 90.0,
    "Administration": 75.0,
    "Extern/Sonstige": 100.0,
}

USER_ROLES = [
    "Administrator",
    "Geschäftsführung",
    "Programmierung",
    "Controlling",
    "Administration",
    "Leser",
]

ROLE_PERMISSIONS = {
    "Administrator": {"edit": True, "users": True, "rates": True, "import": True, "export": True},
    "Geschäftsführung": {"edit": True, "users": False, "rates": True, "import": True, "export": True},
    "Programmierung": {"edit": True, "users": False, "rates": False, "import": False, "export": True},
    "Controlling": {"edit": True, "users": False, "rates": True, "import": False, "export": True},
    "Administration": {"edit": True, "users": False, "rates": False, "import": True, "export": True},
    "Leser": {"edit": False, "users": False, "rates": False, "import": False, "export": True},
}


# ------------------------- Styling ---------------------------

st.markdown(
    """
    <style>
    .ccdata-title {font-size: 2.0rem; font-weight: 800; margin-bottom: 0;}
    .ccdata-subtitle {color: #5f6b7a; margin-top: 0;}
    div[data-testid="stMetric"] {
        border: 1px solid #d9e2f3;
        border-radius: 10px;
        padding: 12px;
        background: #ffffff;
    }
    .small-note {font-size: .85rem; color: #6b7280;}
    </style>
    """,
    unsafe_allow_html=True,
)


# ------------------------- Helpers ---------------------------

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def hash_password(password: str) -> str:
    """Hash a password with PBKDF2-HMAC-SHA256 using only Python stdlib."""
    iterations = 310_000
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(derived).decode("ascii"),
    )


def check_password(password: str, stored: str) -> bool:
    """Verify a password created by hash_password()."""
    try:
        algorithm, iterations, salt_b64, hash_b64 = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
        expected = base64.urlsafe_b64decode(hash_b64.encode("ascii"))
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            int(iterations),
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def money(value: float) -> str:
    return f"{float(value):,.2f} €".replace(",", "X").replace(".", ",").replace("X", ".")


def hours(value: float) -> str:
    return f"{float(value):,.1f}".replace(",", "X").replace(".", ",").replace("X", ".")


def clean_value(value):
    if pd.isna(value):
        return None
    if isinstance(value, (pd.Timestamp, datetime)):
        return value.isoformat()
    return value


def init_db():
    conn = db()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            display_name TEXT,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS rates (
            resource_role TEXT PRIMARY KEY,
            hourly_rate REAL NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS attributes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_group TEXT NOT NULL,
            category TEXT,
            attribute TEXT,
            data_domain TEXT,
            description TEXT,
            data_type TEXT,
            mandatory_level TEXT,
            derivation TEXT,
            technical_field_id TEXT,
            approval_comment TEXT,
            decision_programming TEXT,
            decision_controlling TEXT,
            development_priority TEXT,
            complexity TEXT,
            effort_hours REAL NOT NULL DEFAULT 0,
            resource_role TEXT NOT NULL DEFAULT 'Programmierung',
            status TEXT NOT NULL DEFAULT 'Offen',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            updated_by TEXT
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            username TEXT,
            action TEXT NOT NULL,
            details TEXT
        )
        """
    )

    cur.execute("SELECT COUNT(*) AS c FROM users")
    if cur.fetchone()["c"] == 0:
        # First-run admin. Override with environment variables in production.
        username = os.getenv("CCDATA_ADMIN_USER", "admin")
        password = os.getenv("CCDATA_ADMIN_PASSWORD", "ChangeMe-CCDATA-2026!")
        cur.execute(
            """
            INSERT INTO users (username, display_name, password_hash, role, active, created_at)
            VALUES (?, ?, ?, ?, 1, ?)
            """,
            (username, "CCDATA Administrator", hash_password(password), "Administrator", now_iso()),
        )

    for role_name, rate in DEFAULT_ROLES.items():
        cur.execute(
            "INSERT OR IGNORE INTO rates (resource_role, hourly_rate) VALUES (?, ?)",
            (role_name, rate),
        )

    conn.commit()
    conn.close()


def log_action(username: str, action: str, details: str = ""):
    conn = db()
    conn.execute(
        "INSERT INTO audit_log (event_time, username, action, details) VALUES (?, ?, ?, ?)",
        (now_iso(), username, action, details[:4000]),
    )
    conn.commit()
    conn.close()


def authenticate(username: str, password: str):
    conn = db()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ? AND active = 1", (username,)
    ).fetchone()
    conn.close()
    if row and check_password(password, row["password_hash"]):
        return dict(row)
    return None


def permissions() -> dict:
    role = st.session_state.get("user", {}).get("role", "Leser")
    return ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS["Leser"])


def get_rates() -> pd.DataFrame:
    conn = db()
    df = pd.read_sql_query(
        "SELECT resource_role AS Ressourcenrolle, hourly_rate AS Stundensatz FROM rates ORDER BY resource_role",
        conn,
    )
    conn.close()
    return df


def rate_map() -> dict:
    df = get_rates()
    return dict(zip(df["Ressourcenrolle"], df["Stundensatz"]))


def get_attributes() -> pd.DataFrame:
    conn = db()
    df = pd.read_sql_query(
        """
        SELECT
            id AS ID,
            user_group AS Nutzergruppe,
            category AS Kategorie,
            attribute AS Attribut,
            data_domain AS Datendomäne,
            description AS "Beschreibung / Inhalt",
            data_type AS Datentyp,
            mandatory_level AS Pflichtgrad,
            derivation AS Herleitung,
            technical_field_id AS "Technische Feld-ID",
            approval_comment AS "Freigabe/Kommentar",
            decision_programming AS Entscheidungsebene_Programmierung,
            decision_controlling AS Entscheidungsebene_Controlling,
            development_priority AS Entwicklungspriorität,
            complexity AS Komplexität,
            effort_hours AS "Aufwand in Mannstunden",
            resource_role AS Ressourcenrolle,
            status AS Status,
            updated_at AS Aktualisiert,
            updated_by AS "Aktualisiert durch"
        FROM attributes
        ORDER BY user_group, category, id
        """,
        conn,
    )
    conn.close()

    if not df.empty:
        df["Aufwand in Mannstunden"] = pd.to_numeric(
            df["Aufwand in Mannstunden"], errors="coerce"
        ).fillna(0.0)

    return df


def save_dataframe_changes(edited: pd.DataFrame, username: str):
    conn = db()
    cur = conn.cursor()
    for _, row in edited.iterrows():
        cur.execute(
            """
            UPDATE attributes SET
                category=?,
                attribute=?,
                data_domain=?,
                description=?,
                data_type=?,
                mandatory_level=?,
                derivation=?,
                technical_field_id=?,
                approval_comment=?,
                decision_programming=?,
                decision_controlling=?,
                development_priority=?,
                complexity=?,
                effort_hours=?,
                resource_role=?,
                status=?,
                updated_at=?,
                updated_by=?
            WHERE id=?
            """,
            (
                clean_value(row.get("Kategorie")),
                clean_value(row.get("Attribut")),
                clean_value(row.get("Datendomäne")),
                clean_value(row.get("Beschreibung / Inhalt")),
                clean_value(row.get("Datentyp")),
                clean_value(row.get("Pflichtgrad")),
                clean_value(row.get("Herleitung")),
                clean_value(row.get("Technische Feld-ID")),
                clean_value(row.get("Freigabe/Kommentar")),
                clean_value(row.get("Entscheidungsebene_Programmierung")),
                clean_value(row.get("Entscheidungsebene_Controlling")),
                clean_value(row.get("Entwicklungspriorität")),
                clean_value(row.get("Komplexität")),
                float(pd.to_numeric(row.get("Aufwand in Mannstunden"), errors="coerce") or 0),
                clean_value(row.get("Ressourcenrolle")) or "Programmierung",
                clean_value(row.get("Status")) or "Offen",
                now_iso(),
                username,
                int(row["ID"]),
            ),
        )
    conn.commit()
    conn.close()
    log_action(username, "ATTRIBUTE_UPDATE", f"{len(edited)} Datensätze gespeichert")


def add_attribute(user_group: str, username: str):
    conn = db()
    conn.execute(
        """
        INSERT INTO attributes (
            user_group, category, attribute, data_domain, description, data_type,
            mandatory_level, derivation, technical_field_id, approval_comment,
            decision_programming, decision_controlling, development_priority,
            complexity, effort_hours, resource_role, status,
            created_at, updated_at, updated_by
        )
        VALUES (?, 'Neue Kategorie', 'Neues Attribut', '', '', '', '', '', '', '',
                '', '', 'Mittel', 'Mittel', 0, 'Programmierung', 'Offen', ?, ?, ?)
        """,
        (user_group, now_iso(), now_iso(), username),
    )
    conn.commit()
    conn.close()
    log_action(username, "ATTRIBUTE_CREATE", user_group)


def delete_attribute(row_id: int, username: str):
    conn = db()
    conn.execute("DELETE FROM attributes WHERE id = ?", (int(row_id),))
    conn.commit()
    conn.close()
    log_action(username, "ATTRIBUTE_DELETE", f"ID={row_id}")


def import_excel(file_bytes: bytes, username: str, replace_existing: bool = True) -> tuple[int, list[str]]:
    xls = pd.ExcelFile(io.BytesIO(file_bytes), engine="openpyxl")
    found = [s for s in SOURCE_SHEETS if s in xls.sheet_names]
    if not found:
        raise ValueError(
            "Keine der erwarteten Tabellen gefunden: "
            + ", ".join(SOURCE_SHEETS)
        )

    conn = db()
    cur = conn.cursor()

    if replace_existing:
        cur.execute("DELETE FROM attributes")

    count = 0
    for sheet in found:
        frame = pd.read_excel(xls, sheet_name=sheet, engine="openpyxl")
        frame.columns = [str(c).strip() for c in frame.columns]

        for _, r in frame.iterrows():
            if pd.isna(r.get("Attribut")) and pd.isna(r.get("Kategorie")):
                continue

            effort = pd.to_numeric(r.get("Aufwand in Mannstunden", 0), errors="coerce")
            effort = 0.0 if pd.isna(effort) else float(effort)

            resource_role = clean_value(r.get("Ressourcenrolle")) or "Programmierung"
            status = clean_value(r.get("Status")) or "Offen"

            cur.execute(
                """
                INSERT INTO attributes (
                    user_group, category, attribute, data_domain, description, data_type,
                    mandatory_level, derivation, technical_field_id, approval_comment,
                    decision_programming, decision_controlling, development_priority,
                    complexity, effort_hours, resource_role, status,
                    created_at, updated_at, updated_by
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sheet,
                    clean_value(r.get("Kategorie")),
                    clean_value(r.get("Attribut")),
                    clean_value(r.get("Datendomäne")),
                    clean_value(r.get("Beschreibung / Inhalt")),
                    clean_value(r.get("Datentyp")),
                    clean_value(r.get("Pflichtgrad")),
                    clean_value(r.get("Herleitung")),
                    clean_value(r.get("Technische Feld-ID")),
                    clean_value(r.get("Freigabe/Kommentar")),
                    clean_value(r.get("Entscheidungsebene_Programmierung")),
                    clean_value(r.get("Entscheidungsebene_Controlling")),
                    clean_value(r.get("Entwicklungspriorität")),
                    clean_value(r.get("Komplexität")),
                    effort,
                    resource_role,
                    status,
                    now_iso(),
                    now_iso(),
                    username,
                ),
            )
            count += 1

    conn.commit()
    conn.close()
    log_action(username, "EXCEL_IMPORT", f"{count} Attribute; Blätter={found}")
    return count, found


def cost_detail(attributes: pd.DataFrame) -> pd.DataFrame:
    if attributes.empty:
        return pd.DataFrame()

    rates = rate_map()
    df = attributes.copy()
    df["Stundensatz"] = df["Ressourcenrolle"].map(rates).fillna(DEFAULT_RATE)
    df["Kosten"] = df["Aufwand in Mannstunden"] * df["Stundensatz"]
    return df


def cost_summary(attributes: pd.DataFrame) -> pd.DataFrame:
    df = cost_detail(attributes)
    if df.empty:
        return pd.DataFrame(
            columns=["Nutzergruppe", "Kategorie", "Attribute", "Mannstunden", "Kosten"]
        )

    result = (
        df.groupby(["Nutzergruppe", "Kategorie"], dropna=False)
        .agg(
            Attribute=("ID", "count"),
            Mannstunden=("Aufwand in Mannstunden", "sum"),
            Kosten=("Kosten", "sum"),
        )
        .reset_index()
    )
    return result


def to_excel_bytes(attributes: pd.DataFrame) -> bytes:
    output = io.BytesIO()
    detail = cost_detail(attributes)
    summary = cost_summary(attributes)
    rates = get_rates()

    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        for group in SOURCE_SHEETS:
            group_df = attributes[attributes["Nutzergruppe"] == group].copy()
            cols = [c for c in group_df.columns if c not in ["Nutzergruppe"]]
            group_df[cols].to_excel(writer, sheet_name=group[:31], index=False)

        summary.to_excel(writer, sheet_name="Kostenmonitor", index=False)
        rates.to_excel(writer, sheet_name="Stundensaetze", index=False)
        detail.to_excel(writer, sheet_name="Gesamtdaten", index=False)

    return output.getvalue()


# ------------------------- Login -----------------------------

def login_screen():
    st.markdown(f'<div class="ccdata-title">{COMPANY_NAME}</div>', unsafe_allow_html=True)
    st.markdown(
        f'<div class="ccdata-subtitle">{APP_NAME}</div>',
        unsafe_allow_html=True,
    )
    st.divider()

    left, center, right = st.columns([1.2, 1, 1.2])
    with center:
        st.subheader("Anmeldung")
        with st.form("login"):
            username = st.text_input("Benutzername")
            password = st.text_input("Passwort", type="password")
            submitted = st.form_submit_button("Anmelden", use_container_width=True)

        if submitted:
            user = authenticate(username.strip(), password)
            if user:
                st.session_state.user = user
                log_action(user["username"], "LOGIN")
                st.rerun()
            else:
                st.error("Benutzername oder Passwort ist nicht korrekt.")

        st.caption(
            "Erstanmeldung: Benutzername `admin`. "
            "Das Startpasswort wird in der README beschrieben und sollte sofort geändert werden."
        )


# ------------------------- Pages -----------------------------

def dashboard_page():
    st.header("Dashboard")
    attrs = get_attributes()
    detail = cost_detail(attrs)
    summary = cost_summary(attrs)

    total_hours = detail["Aufwand in Mannstunden"].sum() if not detail.empty else 0
    total_cost = detail["Kosten"].sum() if not detail.empty else 0
    total_attributes = len(detail)
    completed = (
        (detail["Status"].fillna("") == "Erledigt").sum() if not detail.empty else 0
    )

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Attribute", f"{total_attributes}")
    c2.metric("Mannstunden", hours(total_hours))
    c3.metric("Budget", money(total_cost))
    c4.metric("Erledigt", f"{completed} / {total_attributes}")

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("Kosten nach Nutzergruppe")
        if not detail.empty:
            chart_df = (
                detail.groupby("Nutzergruppe", as_index=False)["Kosten"].sum()
                .sort_values("Kosten", ascending=False)
            )
            fig = px.bar(
                chart_df,
                x="Nutzergruppe",
                y="Kosten",
                text_auto=".2s",
                title=None,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Noch keine Daten vorhanden.")

    with right:
        st.subheader("Mannstunden nach Kategorie")
        if not summary.empty:
            chart_df = (
                summary.groupby("Kategorie", as_index=False)["Mannstunden"].sum()
                .sort_values("Mannstunden", ascending=False)
                .head(15)
            )
            fig = px.bar(
                chart_df,
                x="Mannstunden",
                y="Kategorie",
                orientation="h",
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Noch keine Daten vorhanden.")

    st.subheader("Kostenübersicht")
    if not summary.empty:
        show = summary.copy()
        show["Mannstunden"] = show["Mannstunden"].round(1)
        show["Kosten"] = show["Kosten"].round(2)
        st.dataframe(
            show,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Kosten": st.column_config.NumberColumn("Kosten", format="%.2f €"),
                "Mannstunden": st.column_config.NumberColumn("Mannstunden", format="%.1f h"),
            },
        )


def attributes_page():
    st.header("Attribute & Pflichtenheft")
    attrs = get_attributes()
    perms = permissions()

    if attrs.empty:
        st.warning("Noch keine Attribute vorhanden. Bitte zunächst eine Excel-Datei importieren.")
        return

    f1, f2, f3, f4 = st.columns(4)
    groups = ["Alle"] + SOURCE_SHEETS
    selected_group = f1.selectbox("Nutzergruppe", groups)

    categories = sorted(attrs["Kategorie"].dropna().astype(str).unique().tolist())
    selected_category = f2.selectbox("Kategorie", ["Alle"] + categories)

    priorities = sorted(
        [x for x in attrs["Entwicklungspriorität"].dropna().astype(str).unique().tolist() if x]
    )
    selected_priority = f3.selectbox("Priorität", ["Alle"] + priorities)

    search = f4.text_input("Suche", placeholder="Attribut, Beschreibung, Feld-ID …")

    filtered = attrs.copy()
    if selected_group != "Alle":
        filtered = filtered[filtered["Nutzergruppe"] == selected_group]
    if selected_category != "Alle":
        filtered = filtered[filtered["Kategorie"] == selected_category]
    if selected_priority != "Alle":
        filtered = filtered[filtered["Entwicklungspriorität"] == selected_priority]
    if search:
        search_mask = filtered.astype(str).apply(
            lambda col: col.str.contains(search, case=False, na=False)
        ).any(axis=1)
        filtered = filtered[search_mask]

    display_cols = [
        "ID",
        "Nutzergruppe",
        "Kategorie",
        "Attribut",
        "Datendomäne",
        "Beschreibung / Inhalt",
        "Datentyp",
        "Pflichtgrad",
        "Herleitung",
        "Technische Feld-ID",
        "Freigabe/Kommentar",
        "Entscheidungsebene_Programmierung",
        "Entscheidungsebene_Controlling",
        "Entwicklungspriorität",
        "Komplexität",
        "Aufwand in Mannstunden",
        "Ressourcenrolle",
        "Status",
    ]

    rates = get_rates()["Ressourcenrolle"].tolist()

    edited = st.data_editor(
        filtered[display_cols],
        use_container_width=True,
        hide_index=True,
        disabled=[] if perms["edit"] else display_cols,
        num_rows="fixed",
        column_config={
            "ID": st.column_config.NumberColumn("ID", disabled=True),
            "Nutzergruppe": st.column_config.SelectboxColumn(
                "Nutzergruppe", options=SOURCE_SHEETS, disabled=True
            ),
            "Entwicklungspriorität": st.column_config.SelectboxColumn(
                "Entwicklungspriorität",
                options=["Kritisch", "Hoch", "Mittel", "Niedrig"],
            ),
            "Komplexität": st.column_config.SelectboxColumn(
                "Komplexität",
                options=["Sehr hoch", "Hoch", "Mittel", "Niedrig"],
            ),
            "Aufwand in Mannstunden": st.column_config.NumberColumn(
                "Aufwand in Mannstunden", min_value=0.0, step=0.5, format="%.1f"
            ),
            "Ressourcenrolle": st.column_config.SelectboxColumn(
                "Ressourcenrolle", options=rates
            ),
            "Status": st.column_config.SelectboxColumn(
                "Status", options=["Offen", "In Klärung", "Freigegeben", "In Umsetzung", "Erledigt"]
            ),
        },
        key="attributes_editor",
    )

    if perms["edit"]:
        c1, c2, c3 = st.columns([1, 1, 3])
        if c1.button("Änderungen speichern", type="primary"):
            save_dataframe_changes(edited, st.session_state.user["username"])
            st.success("Änderungen wurden gespeichert.")
            st.rerun()

        with c2.popover("Attribut hinzufügen"):
            add_group = st.selectbox("Nutzergruppe", SOURCE_SHEETS, key="add_group")
            if st.button("Neuen Datensatz anlegen"):
                add_attribute(add_group, st.session_state.user["username"])
                st.rerun()

        with c3.popover("Attribut löschen"):
            delete_id = st.number_input("ID", min_value=1, step=1)
            st.warning("Der Datensatz wird dauerhaft gelöscht.")
            if st.button("ID löschen"):
                delete_attribute(int(delete_id), st.session_state.user["username"])
                st.rerun()


def costs_page():
    st.header("Kostenmonitor")
    attrs = get_attributes()
    detail = cost_detail(attrs)
    summary = cost_summary(attrs)

    if detail.empty:
        st.info("Noch keine Daten vorhanden.")
        return

    f1, f2 = st.columns(2)
    group = f1.selectbox("Nutzergruppe", ["Alle"] + SOURCE_SHEETS, key="cost_group")
    role_options = ["Alle"] + sorted(detail["Ressourcenrolle"].dropna().unique().tolist())
    role = f2.selectbox("Ressourcenrolle", role_options)

    filtered = detail.copy()
    if group != "Alle":
        filtered = filtered[filtered["Nutzergruppe"] == group]
    if role != "Alle":
        filtered = filtered[filtered["Ressourcenrolle"] == role]

    total_hours = filtered["Aufwand in Mannstunden"].sum()
    total_cost = filtered["Kosten"].sum()

    c1, c2, c3 = st.columns(3)
    c1.metric("Mannstunden", hours(total_hours))
    c2.metric("Kosten", money(total_cost))
    c3.metric(
        "Ø Kosten / Attribut",
        money(total_cost / len(filtered)) if len(filtered) else money(0),
    )

    st.subheader("Nach Bereich und Kategorie")
    group_summary = (
        filtered.groupby(["Nutzergruppe", "Kategorie"], dropna=False)
        .agg(
            Attribute=("ID", "count"),
            Mannstunden=("Aufwand in Mannstunden", "sum"),
            Kosten=("Kosten", "sum"),
        )
        .reset_index()
    )

    st.dataframe(
        group_summary,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Kosten": st.column_config.NumberColumn("Kosten", format="%.2f €"),
            "Mannstunden": st.column_config.NumberColumn("Mannstunden", format="%.1f h"),
        },
    )

    chart = (
        filtered.groupby("Nutzergruppe", as_index=False)["Kosten"]
        .sum()
        .sort_values("Kosten", ascending=False)
    )
    fig = px.pie(chart, values="Kosten", names="Nutzergruppe", hole=0.45)
    st.plotly_chart(fig, use_container_width=True)


def rates_page():
    st.header("Stundensätze")
    perms = permissions()
    rates = get_rates()

    edited = st.data_editor(
        rates,
        use_container_width=True,
        hide_index=True,
        disabled=[] if perms["rates"] else ["Ressourcenrolle", "Stundensatz"],
        column_config={
            "Stundensatz": st.column_config.NumberColumn(
                "Stundensatz", min_value=0.0, step=5.0, format="%.2f €"
            )
        },
    )

    if perms["rates"] and st.button("Stundensätze speichern", type="primary"):
        conn = db()
        for _, row in edited.iterrows():
            conn.execute(
                "INSERT OR REPLACE INTO rates(resource_role, hourly_rate) VALUES (?, ?)",
                (str(row["Ressourcenrolle"]), float(row["Stundensatz"])),
            )
        conn.commit()
        conn.close()
        log_action(st.session_state.user["username"], "RATE_UPDATE")
        st.success("Stundensätze gespeichert.")
        st.rerun()


def import_export_page():
    st.header("Import & Export")
    perms = permissions()

    if perms["import"]:
        st.subheader("Excel importieren")
        st.write(
            "Unterstützt werden die vier Arbeitsblätter "
            "`Unternehmen`, `Trainer`, `CCData Admin` und `Teilnehmer`."
        )
        upload = st.file_uploader("CCDATA Excel-Datei", type=["xlsx"])
        replace = st.checkbox(
            "Bestehende Attribute beim Import vollständig ersetzen",
            value=True,
        )

        if upload and st.button("Excel importieren", type="primary"):
            try:
                count, sheets = import_excel(
                    upload.getvalue(),
                    st.session_state.user["username"],
                    replace_existing=replace,
                )
                st.success(
                    f"{count} Attribute importiert. Erkannte Blätter: {', '.join(sheets)}"
                )
                st.rerun()
            except Exception as exc:
                st.error(f"Import fehlgeschlagen: {exc}")

    st.divider()
    st.subheader("Excel exportieren")
    attrs = get_attributes()

    if perms["export"] and not attrs.empty:
        data = to_excel_bytes(attrs)
        st.download_button(
            "Aktuellen Stand als Excel herunterladen",
            data=data,
            file_name=f"CCDATA_Projektmonitor_{datetime.now():%Y%m%d_%H%M}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )


def users_page():
    st.header("Benutzerverwaltung")
    if not permissions()["users"]:
        st.error("Keine Berechtigung für die Benutzerverwaltung.")
        return

    conn = db()
    users = pd.read_sql_query(
        """
        SELECT id AS ID, username AS Benutzername, display_name AS Name,
               role AS Rolle, active AS Aktiv, created_at AS Angelegt
        FROM users ORDER BY username
        """,
        conn,
    )
    conn.close()

    st.dataframe(users, use_container_width=True, hide_index=True)

    st.subheader("Benutzer anlegen")
    with st.form("create_user"):
        c1, c2 = st.columns(2)
        username = c1.text_input("Benutzername")
        display_name = c2.text_input("Name")
        role = c1.selectbox("Rolle", USER_ROLES)
        password = c2.text_input("Startpasswort", type="password")
        create = st.form_submit_button("Benutzer anlegen")

    if create:
        if not username or len(password) < 10:
            st.error("Benutzername angeben; Passwort muss mindestens 10 Zeichen haben.")
        else:
            try:
                conn = db()
                conn.execute(
                    """
                    INSERT INTO users(username, display_name, password_hash, role, active, created_at)
                    VALUES (?, ?, ?, ?, 1, ?)
                    """,
                    (username.strip(), display_name.strip(), hash_password(password), role, now_iso()),
                )
                conn.commit()
                conn.close()
                log_action(st.session_state.user["username"], "USER_CREATE", username)
                st.success("Benutzer angelegt.")
                st.rerun()
            except sqlite3.IntegrityError:
                st.error("Dieser Benutzername existiert bereits.")

    st.subheader("Passwort / Rolle / Status ändern")
    if not users.empty:
        selected = st.selectbox(
            "Benutzer",
            users["Benutzername"].tolist(),
            key="manage_user",
        )
        current = users[users["Benutzername"] == selected].iloc[0]
        c1, c2, c3 = st.columns(3)
        new_role = c1.selectbox(
            "Rolle",
            USER_ROLES,
            index=USER_ROLES.index(current["Rolle"]) if current["Rolle"] in USER_ROLES else 0,
        )
        active = c2.checkbox("Aktiv", value=bool(current["Aktiv"]))
        new_password = c3.text_input("Neues Passwort (optional)", type="password")

        if st.button("Benutzer aktualisieren"):
            conn = db()
            if new_password:
                if len(new_password) < 10:
                    st.error("Das Passwort muss mindestens 10 Zeichen haben.")
                    conn.close()
                    return
                conn.execute(
                    "UPDATE users SET role=?, active=?, password_hash=? WHERE username=?",
                    (new_role, int(active), hash_password(new_password), selected),
                )
            else:
                conn.execute(
                    "UPDATE users SET role=?, active=? WHERE username=?",
                    (new_role, int(active), selected),
                )
            conn.commit()
            conn.close()
            log_action(st.session_state.user["username"], "USER_UPDATE", selected)
            st.success("Benutzer aktualisiert.")
            st.rerun()


def audit_page():
    st.header("Audit-Log")
    conn = db()
    logs = pd.read_sql_query(
        """
        SELECT event_time AS Zeitpunkt, username AS Benutzer,
               action AS Aktion, details AS Details
        FROM audit_log ORDER BY id DESC LIMIT 1000
        """,
        conn,
    )
    conn.close()
    st.dataframe(logs, use_container_width=True, hide_index=True)


# ------------------------- Application -----------------------

init_db()

if "user" not in st.session_state:
    login_screen()
    st.stop()

user = st.session_state.user

with st.sidebar:
    st.markdown(f"## {COMPANY_NAME}")
    st.caption(APP_NAME)
    st.write(f"**{user.get('display_name') or user['username']}**")
    st.caption(f"Rolle: {user['role']}")
    st.divider()

    pages = ["Dashboard", "Attribute & Pflichtenheft", "Kostenmonitor", "Stundensätze", "Import & Export"]
    if permissions()["users"]:
        pages += ["Benutzerverwaltung", "Audit-Log"]

    page = st.radio("Navigation", pages)

    st.divider()
    if st.button("Abmelden", use_container_width=True):
        log_action(user["username"], "LOGOUT")
        st.session_state.clear()
        st.rerun()

st.markdown(f'<div class="ccdata-title">{COMPANY_NAME}</div>', unsafe_allow_html=True)
st.markdown(
    f'<div class="ccdata-subtitle">{APP_NAME}</div>',
    unsafe_allow_html=True,
)

if page == "Dashboard":
    dashboard_page()
elif page == "Attribute & Pflichtenheft":
    attributes_page()
elif page == "Kostenmonitor":
    costs_page()
elif page == "Stundensätze":
    rates_page()
elif page == "Import & Export":
    import_export_page()
elif page == "Benutzerverwaltung":
    users_page()
elif page == "Audit-Log":
    audit_page()
