from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections import defaultdict, deque
import sqlite3
import time


from src.common import config
from src.system import containment as containment_backend


@dataclass
class Alert:
    src_ip: str
    probability: float
    timestamp: str

@dataclass
class Case:
    case_id: int
    src_ip: str
    severity: str
    action: str
    probability: float
    created_at: str
    updated_at: str
    alert_count: int = 1
    alerts: list[Alert] = field(default_factory=list)
    blocked_at_severity: str | None = None
    rate_trigger: str | None = None

class SOAREngine:

    def __init__(self, containment=containment_backend):
        self.containment = containment
        self.cases = {}
        self.next_case_id = 1
        self.latencies = []
        self.recent_flows = defaultdict(deque)
        self.recent_auth_flows = defaultdict(deque)
        self.init_db()
        self.load_cases()

        if self.current_mode() == "enforce":
            try:
                self.containment.setup()
            except Exception as exc:
                print("[soar] containment setup failed:", exc)


    def init_db(self):
        connection = sqlite3.connect(config.CASES_DB)

        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id INTEGER PRIMARY KEY,
                src_ip TEXT NOT NULL,
                severity TEXT NOT NULL,
                action TEXT NOT NULL,
                probability REAL NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                alert_count INTEGER NOT NULL,
                detection TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                src_ip TEXT NOT NULL,
                probability REAL NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
            )
        """)

        connection.commit()
        connection.close()


    def save_case(self, case):
        connection = sqlite3.connect(config.CASES_DB)

        cursor = connection.cursor()

        cursor.execute("""
            INSERT OR REPLACE INTO cases (
                case_id,
                src_ip,
                severity,
                action,
                probability,
                created_at,
                updated_at,
                alert_count,
                detection
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            case.case_id,
            case.src_ip,
            case.severity,
            case.action,
            case.probability,
            case.created_at,
            case.updated_at,
            case.alert_count,
            case.rate_trigger
        ))

        connection.commit()
        connection.close()

    def save_alert(self, case, alert):
        connection = sqlite3.connect(config.CASES_DB)

        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO alerts (
                case_id,
                src_ip,
                probability,
                timestamp
            )
            VALUES (?, ?, ?, ?)
        """, (
            case.case_id,
            alert.src_ip,
            alert.probability,
            alert.timestamp
        ))

        connection.commit()
        connection.close()
        

    def load_cases(self):
        connection = sqlite3.connect(config.CASES_DB)
        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                case_id,
                src_ip,
                severity,
                action,
                probability,
                created_at,
                updated_at,
                alert_count,
                detection
            FROM cases
            ORDER BY case_id
        """)

        rows = cursor.fetchall()

        for row in rows:
            case = Case(
                case_id=row[0],
                src_ip=row[1],
                severity=row[2],
                action=row[3],
                probability=row[4],
                created_at=row[5],
                updated_at=row[6],
                alert_count=row[7],
                alerts=[],
                blocked_at_severity=row[2] if row[3] == "BLOCK" else None,
                rate_trigger=row[8]
            )

            cursor.execute("""
                SELECT
                    src_ip,
                    probability,
                    timestamp
                FROM alerts
                WHERE case_id = ?
                ORDER BY id
            """, (case.case_id,))

            alert_rows = cursor.fetchall()

            for alert_row in alert_rows:
                alert = Alert(
                    src_ip=alert_row[0],
                    probability=alert_row[1],
                    timestamp=alert_row[2]
                )

                case.alerts.append(alert)

            if (row[3] != "CLOSED"
                    and self._age_seconds(case.updated_at) <= config.CASE_TTL_SECONDS):
                self.cases[case.src_ip] = case

        if rows:
            self.next_case_id = max(row[0] for row in rows) + 1


        connection.close()


    def ingest(self, flow, probability):
        timestamp = datetime.now(timezone.utc).isoformat()

        return Alert(
            src_ip=flow.src_ip, 
            probability=probability,
            timestamp=timestamp
            )

    def enrich(self, alert):

        return {
            "alert" : alert,
            "whitelisted" : alert.src_ip in config.WHITELIST,
            "internal" : alert.src_ip.startswith("192.168."),
        }

    def correlate(self, alert):

        case = self.cases.get(alert.src_ip)

        if case is not None and self._age_seconds(case.updated_at) > config.CASE_TTL_SECONDS:
            case = None
            
        if case is not None and self._is_closed(case.case_id):
            self.cases.pop(alert.src_ip, None)
            case = None
        

        if case is None:

            case = Case(
                case_id=self.next_case_id,
                src_ip=alert.src_ip,
                severity="LOW",
                action="MONITOR",
                probability=alert.probability,
                created_at=alert.timestamp,
                updated_at=alert.timestamp,
                alerts = [alert]
            )

            self.cases[alert.src_ip] = case
            self.next_case_id += 1


        else:

            case.alerts.append(alert)
            case.alert_count += 1
            case.updated_at = alert.timestamp

            if alert.probability > case.probability:
                
                case.probability = alert.probability


        return case



    def close_case(self, src_ip):
        
        case = self.cases.pop(src_ip, None)

        if case is None:
            return False

        case.action = "CLOSED"
        self.save_case(case)
        return True

    def _rate(self, history, window, now):
        
        while history and now - history[0] > window:
            history.popleft()
        return len(history)

    def observe(self, flow):

        now = flow.timestamps[-1] if flow.timestamps else time.time()
        source = flow.src_ip

        history = self.recent_flows[source]
        history.append(now)
        flows_in_window = self._rate(history, config.RATE_WINDOW_SECONDS, now)

        auth_in_window = 0

        if getattr(flow, "dst_port", None) in config.AUTH_PORTS:
            auth_history = self.recent_auth_flows[source]
            auth_history.append(now)
            auth_in_window = self._rate(
                auth_history, config.AUTH_RATE_WINDOW, now
            )

        # Auth first: it is the more specific finding and the better label.
        if auth_in_window >= config.AUTH_RATE_THRESHOLD:
            return "AUTH_BRUTE_FORCE"

        if flows_in_window >= config.RATE_FLOWS_THRESHOLD:
            return "FLOOD"

        return None

    def triage(self, case):

        probability = case.probability

        if case.rate_trigger:
            severity = "HIGH"

        elif probability >= config.SEV_HIGH:
            severity = "HIGH"

        elif case.alert_count >= config.ESCALATE_TO_HIGH:
            # Sustained burst: many flows from one source, correlated.
            severity = "HIGH"

        elif case.alert_count >= config.ESCALATE_TO_MEDIUM:
            # Repeated, but not yet a burst.
            severity = "MEDIUM"

        else:
            # First sightings at moderate confidence. Log and watch.
            severity = "LOW"

        case.severity = severity
        return case

    def decide(self,  case):

        if case.severity == "HIGH":
            action = "BLOCK"
            ttl = config.BLOCK_TTL_SECONDS

        elif case.severity == "MEDIUM":
            action = "BLOCK"
            ttl = config.SHORT_BLOCK_TTL

        else:
            action = "MONITOR"
            ttl = 0

        if self.current_mode() == "monitor":
            effective_action = "MONITOR"

        elif self.current_mode() == "alert":
            effective_action = "ALERT"

        elif self.current_mode() == "enforce":
            effective_action = action

        else:
            raise ValueError(
                f"Unknown SOAR mode: {self.current_mode()}"
            )

        case.action = effective_action

        return{
            "case": case, 
            "action": effective_action, 
            "ttl": ttl}

    def apply(self, case, decision):

        if decision["action"] != "BLOCK":
            return

        escalated = case.severity != case.blocked_at_severity

        try:
            if not escalated and self.containment.is_blocked(case.src_ip):
                return

            blocked = self.containment.block(case.src_ip, decision["ttl"])

        except Exception as exc:
            print("[soar] containment failed for", case.src_ip, ":", exc)
            case.action = "BLOCK_FAILED"
            return

        if blocked:
            case.blocked_at_severity = case.severity
            self.record_latency(case)

        else:
            case.action = "BLOCK_REFUSED"


    def record_latency(self, case):

        seconds = self._age_seconds(case.created_at)

        if seconds == float("inf"):
            return

        self.latencies.append(seconds)

        with open(config.LATENCY_LOG, "a") as handle:
            handle.write(
                f"{case.case_id},{case.src_ip},{case.severity},"
                f"{case.alert_count},{seconds:.4f}\n"
            )

    def latency_report(self):
        """p50 and p95 of containment latency, as section 11.2 requires."""
        if not self.latencies:
            return None

        ordered = sorted(self.latencies)

        def percentile(p):
            index = min(int(len(ordered) * p), len(ordered) - 1)
            return ordered[index]

        return {
            "n": len(ordered),
            "p50": percentile(0.50),
            "p95": percentile(0.95),
            "max": ordered[-1],
        }
    
    def _age_seconds(self, iso_timestamp):

        try:
            then = datetime.fromisoformat(iso_timestamp)
        except (TypeError, ValueError):
            return float("inf")
        return (datetime.now(timezone.utc) - then).total_seconds()

    def _is_closed(self, case_id):

        connection = sqlite3.connect(config.CASES_DB)
        row = connection.execute(
            "SELECT action FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        connection.close()

        return row is not None and row[0] == "CLOSED"
    
    def current_mode(self):

        try:
            with open(config.RUNTIME_MODE_FILE) as handle:
                mode = handle.read().strip()
            if mode in ("monitor", "alert", "enforce"):
                return mode
        except (OSError, ValueError):
            pass
        return config.MODE
    

    def process_alert(self, flow, probability, partial=False):

        alert = self.ingest(flow, probability)

        if partial:
            return {
                "case": None,
                "alert": alert,
                "severity": "PARTIAL",
                "action": "MONITOR",
                "ttl": 0,
            }

        rate_trigger = self.observe(flow)

        if rate_trigger is None and alert.probability < config.THRESHOLD:
            return {
                "case": None,
                "alert": alert,
                "severity": "BELOW_THRESHOLD",
                "action": "IGNORE",
                "ttl": 0,
            }

        enriched = self.enrich(alert)

        if enriched["whitelisted"]:

            return{
                "case": None,
                "alert": alert,
                "severity": "WHITELISTED",
                "action": "MONITOR",
                "ttl": 0
                }

        case = self.correlate(alert)

        if rate_trigger:
            case.rate_trigger = rate_trigger

        case = self.triage(case)
        decision = self.decide(case)
        self.apply(case, decision)
        self.save_case(case)
        self.save_alert(case, alert)

        return {
            "case": decision["case"],
            "alert": alert,
            "severity": case.severity,
            "action": decision["action"],
            "ttl": decision["ttl"]
        }

    

    