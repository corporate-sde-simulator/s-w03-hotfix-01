"""
====================================================================
 JIRA: SVC-1870 — Fix REST API Rate Limiter Bypass
====================================================================
 P0 | Points: 2 | Labels: api, python, security
 
 Rate limiter tracks by API key but ignores the X-Forwarded-For
 header, letting attackers cycle through IPs. Also, the sliding
 window resets completely instead of sliding.
 
 ACCEPTANCE CRITERIA:
 - [ ] Rate limit tracks by API key (not IP alone)
 - [ ] Sliding window decrements expired requests
 - [ ] Return 429 with Retry-After header when exceeded
====================================================================
"""

import time
from collections import defaultdict

class RateLimiter:
    def __init__(self, max_requests=100, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)

    def is_allowed(self, client_id):
        now = time.time()
        window_start = now - self.window_seconds

        # BUG: Never cleans up old entries — memory grows unbounded
        history = self.requests[client_id]

        # Count requests in window
        # BUG: Counts ALL requests, not just those within window
        count = len(history)

        if count >= self.max_requests:
            return False, {'retry_after': self.window_seconds}

        history.append(now)
        return True, {}

    def get_remaining(self, client_id):
        # BUG: Always returns max_requests (doesn't subtract current usage)
        return self.max_requests


# Tests
if __name__ == '__main__':
    limiter = RateLimiter(max_requests=5, window_seconds=2)
    for i in range(5):
        ok, _ = limiter.is_allowed("key-1")
        assert ok, "FAIL: First 5 should be allowed"

    ok, info = limiter.is_allowed("key-1")
    assert not ok, "FAIL: 6th request should be rejected"

    time.sleep(2.5)
    ok, _ = limiter.is_allowed("key-1")
    assert ok, "FAIL: After window expires, should be allowed again"
    print("Rate limiter tests passed!")
