import httpx

BASE = "http://localhost:8080"


def test_metrics():
    r = httpx.get(f"{BASE}/api/metrics", timeout=10)
    assert r.status_code == 200
    d = r.json()
    assert "detection_rate" in d
    assert "total_events" in d
    print(f"Metrics: {d['total_events']} events, dr={d['detection_rate']}")


def test_sessions():
    r = httpx.get(f"{BASE}/api/sessions", timeout=10)
    assert r.status_code == 200
    print(f"Sessions: {len(r.json())} sessions found")


def test_compliance():
    r = httpx.get(f"{BASE}/api/compliance", timeout=10)
    assert r.status_code == 200
    print(f"Compliance: {len(r.json())} articles mapped")


if __name__ == "__main__":
    test_metrics()
    test_sessions()
    test_compliance()
    print("All API smoke tests passed")
