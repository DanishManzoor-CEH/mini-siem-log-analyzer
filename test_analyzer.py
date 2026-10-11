import unittest
from analyzer import analyze_logs, load_logs


class DetectionRuleTests(unittest.TestCase):
    def test_failed_logins_in_window_trigger_alert(self):
        rows = []
        for i in range(5):
            rows.append({"timestamp": f"2026-10-11 09:00:0{i}", "source_ip": "203.0.113.8", "username": "admin", "event_type": "login", "status": "failed", "message": "Failed login"})
        result = analyze_logs(rows, failed_login_threshold=5, time_window_minutes=5)
        self.assertTrue(any("Repeated failed logins" in a["title"] for a in result["alerts"]))

    def test_failures_outside_window_do_not_trigger_bruteforce_alert(self):
        rows = []
        for i in range(5):
            rows.append({"timestamp": f"2026-10-{1+i:02d} 09:00:00", "source_ip": "203.0.113.8", "username": "admin", "event_type": "login", "status": "failed", "message": "Failed login"})
        result = analyze_logs(rows, failed_login_threshold=5, time_window_minutes=5)
        self.assertFalse(any("Repeated failed logins" in a["title"] for a in result["alerts"]))

    def test_windows_event_id_4625_infers_failed_login(self):
        events = load_logs("timestamp,host,source_ip,username,event_id,message\n2026-10-11 09:00:00,pc1,203.0.113.9,admin,4625,An account failed to log on")
        self.assertEqual(events[0]["status"], "failed")
        self.assertEqual(events[0]["event_type"], "login")

    def test_benign_activity_does_not_trigger_alert(self):
        events = [{"timestamp": "2026-10-11 09:00:00", "source_ip": "192.0.2.2", "username": "analyst", "event_type": "login", "status": "success", "message": "Successful login"}]
        result = analyze_logs(events)
        self.assertEqual(result["alerts"], [])

    def test_ssh_failed_password_is_parsed(self):
        events = load_logs("Oct 11 09:01:03 server sshd[120]: Failed password for admin from 203.0.113.25 port 5111 ssh2")
        self.assertEqual(events[0]["status"], "failed")
        self.assertEqual(events[0]["source_ip"], "203.0.113.25")


if __name__ == "__main__":
    unittest.main()
