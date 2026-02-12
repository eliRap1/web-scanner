"""
Load Testing Script for Web Scanner API (Sprint 4 - Issue 7.4)

Tests multiple concurrent users accessing the API endpoints.
Can be run as pytest tests or standalone script.

Usage:
    pytest tests/test_load.py -v
    python tests/test_load.py
"""

import asyncio
import time
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Any
import requests
import pytest

# Configuration
BASE_URL = "http://localhost:8000"
NUM_CONCURRENT_USERS = 10
REQUEST_TIMEOUT = 30


@dataclass
class LoadTestResult:
    """Results from a single request in load testing."""
    success: bool
    response_time: float  # in seconds
    status_code: Optional[int] = None
    error: Optional[str] = None


@dataclass
class LoadTestSummary:
    """Summary of load test results."""
    scenario_name: str
    total_requests: int
    success_count: int
    failure_count: int
    response_times: List[float] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return (self.success_count / self.total_requests) * 100

    @property
    def avg_response_time(self) -> float:
        if not self.response_times:
            return 0.0
        return statistics.mean(self.response_times)

    @property
    def min_response_time(self) -> float:
        if not self.response_times:
            return 0.0
        return min(self.response_times)

    @property
    def max_response_time(self) -> float:
        if not self.response_times:
            return 0.0
        return max(self.response_times)

    @property
    def std_dev_response_time(self) -> float:
        if len(self.response_times) < 2:
            return 0.0
        return statistics.stdev(self.response_times)

    def print_summary(self):
        """Print formatted summary of load test results."""
        print("\n" + "=" * 60)
        print(f"LOAD TEST SUMMARY: {self.scenario_name}")
        print("=" * 60)
        print(f"Total Requests:      {self.total_requests}")
        print(f"Success Count:       {self.success_count}")
        print(f"Failure Count:       {self.failure_count}")
        print(f"Success Rate:        {self.success_rate:.1f}%")
        print("-" * 60)
        print(f"Avg Response Time:   {self.avg_response_time * 1000:.2f} ms")
        print(f"Min Response Time:   {self.min_response_time * 1000:.2f} ms")
        print(f"Max Response Time:   {self.max_response_time * 1000:.2f} ms")
        print(f"Std Dev:             {self.std_dev_response_time * 1000:.2f} ms")
        print("=" * 60 + "\n")


def is_server_running() -> bool:
    """Check if the server is running and accessible."""
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def make_login_request(user_id: int) -> LoadTestResult:
    """Make a single login request."""
    start_time = time.time()
    try:
        # Use unique credentials per user to avoid rate limiting issues
        response = requests.post(
            f"{BASE_URL}/auth/login",
            data={
                "username": f"loadtest_user_{user_id}",
                "password": "testpassword123"
            },
            timeout=REQUEST_TIMEOUT
        )
        elapsed = time.time() - start_time

        # 401 is expected for non-existent users, but request completed successfully
        success = response.status_code in [200, 401, 422]
        return LoadTestResult(
            success=success,
            response_time=elapsed,
            status_code=response.status_code
        )
    except requests.exceptions.RequestException as e:
        elapsed = time.time() - start_time
        return LoadTestResult(
            success=False,
            response_time=elapsed,
            error=str(e)
        )


def make_scan_request(user_id: int, auth_token: Optional[str] = None) -> LoadTestResult:
    """Make a single scan initiation request."""
    start_time = time.time()
    try:
        headers = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        response = requests.post(
            f"{BASE_URL}/scans/",
            json={
                "url": f"http://example{user_id}.com",
                "scan_type": "quick"
            },
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        elapsed = time.time() - start_time

        # 401/403 expected without auth, 200/201 with valid auth
        success = response.status_code in [200, 201, 401, 403, 422]
        return LoadTestResult(
            success=success,
            response_time=elapsed,
            status_code=response.status_code
        )
    except requests.exceptions.RequestException as e:
        elapsed = time.time() - start_time
        return LoadTestResult(
            success=False,
            response_time=elapsed,
            error=str(e)
        )


def make_health_check_request(user_id: int) -> LoadTestResult:
    """Make a health check request (for baseline testing)."""
    start_time = time.time()
    try:
        response = requests.get(
            f"{BASE_URL}/health",
            timeout=REQUEST_TIMEOUT
        )
        elapsed = time.time() - start_time

        return LoadTestResult(
            success=response.status_code == 200,
            response_time=elapsed,
            status_code=response.status_code
        )
    except requests.exceptions.RequestException as e:
        elapsed = time.time() - start_time
        return LoadTestResult(
            success=False,
            response_time=elapsed,
            error=str(e)
        )


def run_concurrent_load_test(
    scenario_name: str,
    request_func: Callable[[int], LoadTestResult],
    num_users: int = NUM_CONCURRENT_USERS
) -> LoadTestSummary:
    """
    Run a load test with concurrent users using ThreadPoolExecutor.

    Args:
        scenario_name: Name of the test scenario
        request_func: Function that takes user_id and returns LoadTestResult
        num_users: Number of concurrent users to simulate

    Returns:
        LoadTestSummary with aggregated results
    """
    results: List[LoadTestResult] = []

    with ThreadPoolExecutor(max_workers=num_users) as executor:
        # Submit all requests concurrently
        futures = {
            executor.submit(request_func, user_id): user_id
            for user_id in range(num_users)
        }

        # Collect results as they complete
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                results.append(LoadTestResult(
                    success=False,
                    response_time=0.0,
                    error=str(e)
                ))

    # Build summary
    success_count = sum(1 for r in results if r.success)
    response_times = [r.response_time for r in results if r.success]

    return LoadTestSummary(
        scenario_name=scenario_name,
        total_requests=len(results),
        success_count=success_count,
        failure_count=len(results) - success_count,
        response_times=response_times
    )


async def make_async_request(
    session_func: Callable[[], Any],
    user_id: int
) -> LoadTestResult:
    """Make an async request using asyncio."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, session_func, user_id)


async def run_async_load_test(
    scenario_name: str,
    request_func: Callable[[int], LoadTestResult],
    num_users: int = NUM_CONCURRENT_USERS
) -> LoadTestSummary:
    """
    Run a load test with concurrent users using asyncio.

    Args:
        scenario_name: Name of the test scenario
        request_func: Function that takes user_id and returns LoadTestResult
        num_users: Number of concurrent users to simulate

    Returns:
        LoadTestSummary with aggregated results
    """
    tasks = [
        make_async_request(request_func, user_id)
        for user_id in range(num_users)
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    processed_results: List[LoadTestResult] = []
    for result in results:
        if isinstance(result, Exception):
            processed_results.append(LoadTestResult(
                success=False,
                response_time=0.0,
                error=str(result)
            ))
        else:
            processed_results.append(result)

    success_count = sum(1 for r in processed_results if r.success)
    response_times = [r.response_time for r in processed_results if r.success]

    return LoadTestSummary(
        scenario_name=scenario_name,
        total_requests=len(processed_results),
        success_count=success_count,
        failure_count=len(processed_results) - success_count,
        response_times=response_times
    )


# Pytest fixtures and tests

@pytest.fixture(scope="module")
def server_available():
    """Check if server is available for testing."""
    return is_server_running()


@pytest.mark.skipif(
    not is_server_running(),
    reason="Server not running at localhost:8000"
)
class TestLoadConcurrentLogin:
    """Load tests for concurrent login attempts."""

    def test_concurrent_login_threadpool(self):
        """Test multiple simultaneous login attempts using ThreadPoolExecutor."""
        summary = run_concurrent_load_test(
            scenario_name="Concurrent Login (ThreadPool)",
            request_func=make_login_request,
            num_users=NUM_CONCURRENT_USERS
        )

        summary.print_summary()

        # Assertions
        assert summary.total_requests == NUM_CONCURRENT_USERS
        assert summary.success_rate >= 80.0, f"Success rate too low: {summary.success_rate}%"
        assert summary.avg_response_time < 5.0, f"Avg response time too high: {summary.avg_response_time}s"

    def test_concurrent_login_asyncio(self):
        """Test multiple simultaneous login attempts using asyncio."""
        summary = asyncio.run(run_async_load_test(
            scenario_name="Concurrent Login (Asyncio)",
            request_func=make_login_request,
            num_users=NUM_CONCURRENT_USERS
        ))

        summary.print_summary()

        assert summary.total_requests == NUM_CONCURRENT_USERS
        assert summary.success_rate >= 80.0


@pytest.mark.skipif(
    not is_server_running(),
    reason="Server not running at localhost:8000"
)
class TestLoadConcurrentScans:
    """Load tests for concurrent scan requests."""

    def test_concurrent_scan_requests(self):
        """Test multiple simultaneous scan initiation requests."""
        summary = run_concurrent_load_test(
            scenario_name="Concurrent Scan Requests",
            request_func=make_scan_request,
            num_users=NUM_CONCURRENT_USERS
        )

        summary.print_summary()

        assert summary.total_requests == NUM_CONCURRENT_USERS
        assert summary.success_rate >= 80.0

    def test_concurrent_scan_requests_asyncio(self):
        """Test concurrent scan requests using asyncio."""
        summary = asyncio.run(run_async_load_test(
            scenario_name="Concurrent Scan Requests (Asyncio)",
            request_func=make_scan_request,
            num_users=NUM_CONCURRENT_USERS
        ))

        summary.print_summary()

        assert summary.total_requests == NUM_CONCURRENT_USERS


@pytest.mark.skipif(
    not is_server_running(),
    reason="Server not running at localhost:8000"
)
class TestLoadHealthCheck:
    """Load tests for health check endpoint (baseline)."""

    def test_concurrent_health_checks(self):
        """Test concurrent health check requests as baseline."""
        summary = run_concurrent_load_test(
            scenario_name="Concurrent Health Checks (Baseline)",
            request_func=make_health_check_request,
            num_users=NUM_CONCURRENT_USERS
        )

        summary.print_summary()

        assert summary.total_requests == NUM_CONCURRENT_USERS
        assert summary.success_rate == 100.0, "Health checks should always succeed"
        assert summary.avg_response_time < 1.0, "Health checks should be fast"


@pytest.mark.skipif(
    not is_server_running(),
    reason="Server not running at localhost:8000"
)
class TestLoadScalability:
    """Scalability tests with varying user counts."""

    @pytest.mark.parametrize("num_users", [5, 10, 20, 50])
    def test_scalability_login(self, num_users):
        """Test login endpoint scalability with increasing users."""
        summary = run_concurrent_load_test(
            scenario_name=f"Login Scalability ({num_users} users)",
            request_func=make_login_request,
            num_users=num_users
        )

        summary.print_summary()

        assert summary.success_rate >= 70.0, f"Failed at {num_users} users"


def run_all_load_tests():
    """Run all load tests as standalone script."""
    print("\n" + "=" * 70)
    print("WEB SCANNER LOAD TESTING SUITE")
    print("=" * 70)

    if not is_server_running():
        print(f"\nERROR: Server not running at {BASE_URL}")
        print("Please start the server and try again.")
        print("  uvicorn app.main:app --reload")
        return

    print(f"\nServer detected at {BASE_URL}")
    print(f"Running tests with {NUM_CONCURRENT_USERS} concurrent users\n")

    all_summaries: List[LoadTestSummary] = []

    # Test 1: Health check baseline
    print("Running: Health Check Baseline...")
    summary = run_concurrent_load_test(
        scenario_name="Health Check (Baseline)",
        request_func=make_health_check_request,
        num_users=NUM_CONCURRENT_USERS
    )
    summary.print_summary()
    all_summaries.append(summary)

    # Test 2: Concurrent login (ThreadPool)
    print("Running: Concurrent Login (ThreadPool)...")
    summary = run_concurrent_load_test(
        scenario_name="Concurrent Login (ThreadPool)",
        request_func=make_login_request,
        num_users=NUM_CONCURRENT_USERS
    )
    summary.print_summary()
    all_summaries.append(summary)

    # Test 3: Concurrent login (Asyncio)
    print("Running: Concurrent Login (Asyncio)...")
    summary = asyncio.run(run_async_load_test(
        scenario_name="Concurrent Login (Asyncio)",
        request_func=make_login_request,
        num_users=NUM_CONCURRENT_USERS
    ))
    summary.print_summary()
    all_summaries.append(summary)

    # Test 4: Concurrent scan requests
    print("Running: Concurrent Scan Requests...")
    summary = run_concurrent_load_test(
        scenario_name="Concurrent Scan Requests",
        request_func=make_scan_request,
        num_users=NUM_CONCURRENT_USERS
    )
    summary.print_summary()
    all_summaries.append(summary)

    # Test 5: Scalability test
    print("Running: Scalability Test (varying user counts)...")
    for num_users in [5, 10, 20]:
        summary = run_concurrent_load_test(
            scenario_name=f"Scalability Test ({num_users} users)",
            request_func=make_login_request,
            num_users=num_users
        )
        summary.print_summary()
        all_summaries.append(summary)

    # Final summary
    print("\n" + "=" * 70)
    print("OVERALL LOAD TEST RESULTS")
    print("=" * 70)
    print(f"{'Scenario':<45} {'Success':<10} {'Avg Time':<12}")
    print("-" * 70)
    for s in all_summaries:
        print(f"{s.scenario_name:<45} {s.success_rate:>6.1f}%    {s.avg_response_time*1000:>8.2f} ms")
    print("=" * 70)

    # Overall pass/fail
    all_passed = all(s.success_rate >= 70.0 for s in all_summaries)
    if all_passed:
        print("\nOVERALL RESULT: PASSED")
    else:
        print("\nOVERALL RESULT: FAILED (some scenarios below 70% success rate)")


if __name__ == "__main__":
    run_all_load_tests()
