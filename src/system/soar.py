from dataclasses import dataclass, field
from datetime import datetime, timezone
import sqlite3

from src.common import config


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

class SOAREngine:

    def __init__(self):
        self.cases = {}
        self.next_case_id = 1
        self.init_db()
        self.load_cases()

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
                alert_count INTEGER NOT NULL
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
                alert_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            case.case_id,
            case.src_ip,
            case.severity,
            case.action,
            case.probability,
            case.created_at,
            case.updated_at,
            case.alert_count
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
                alert_count
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
                alerts=[]
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

    def triage(self, case):

        probability = case.probability

        if probability >= config.SEV_HIGH:
            severity = "HIGH"

        elif probability >= config.SEV_MEDIUM:
            severity = "MEDIUM" 

        elif probability == config.THRESHOLD:
            severity = "LOW"

        else:
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

        if config.MODE == "monitor":
            effective_action = "MONITOR"

        elif config.MODE == "alert":
            effective_action = "ALERT"

        elif config.MODE == "enforce":
            effective_action = action

        else:
            raise ValueError(
                f"Unknown SOAR mode: {config.MODE}"
            )

        case.action = effective_action

        return{
            "case": case, 
            "action": effective_action, 
            "ttl": ttl}


    def process_alert(self, flow, probability):

        alert = self.ingest(
            flow,
            probability
        )

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
        case = self.triage(case)
        decision = self.decide(case)
        self.save_case(case)
        self.save_alert(case, alert)

        return {
            "case": decision["case"],
            "alert": alert,
            "severity": case.severity,
            "action": decision["action"],
            "ttl": decision["ttl"]
        }

    

    