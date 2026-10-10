import unittest
from datetime import datetime, timedelta, timezone


def detect_burst(timestamps, threshold=3, window_minutes=10):
    timestamps = sorted(timestamps)
    window = timedelta(minutes=window_minutes)

    for i, start in enumerate(timestamps):
        matches = [
            timestamp for timestamp in timestamps[i:]
            if timestamp - start <= window
        ]
        if len(matches) >= threshold:
            return True
    return False


class BurstDetectorTests(unittest.TestCase):
    def setUp(self):
        self.start = datetime(2026, 10, 10, 10, 0, tzinfo=timezone.utc)

    def test_three_failures_within_window_detected(self):
        timestamps = [
            self.start,
            self.start + timedelta(minutes=2),
            self.start + timedelta(minutes=4),
        ]
        self.assertTrue(detect_burst(timestamps))

    def test_two_failures_do_not_trigger_alert(self):
        timestamps = [
            self.start,
            self.start + timedelta(minutes=2),
        ]
        self.assertFalse(detect_burst(timestamps))

    def test_failures_outside_window_do_not_trigger_alert(self):
        timestamps = [
            self.start,
            self.start + timedelta(minutes=11),
            self.start + timedelta(minutes=22),
        ]
        self.assertFalse(detect_burst(timestamps))

    def test_exact_window_boundary_is_included(self):
        timestamps = [
            self.start,
            self.start + timedelta(minutes=10),
            self.start + timedelta(minutes=10),
        ]
        self.assertTrue(detect_burst(timestamps))


if __name__ == "__main__":
    unittest.main(verbosity=2)
