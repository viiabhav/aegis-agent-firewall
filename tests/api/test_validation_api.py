from fastapi.testclient import TestClient

from api.main import app


def test_validation_snapshot_is_available():
    client = TestClient(app)
    response = client.get('/api/validation')
    assert response.status_code == 200
    payload = response.json()
    assert 'benchmark_available' in payload
    assert 'replay_report_available' in payload


def test_live_redteam_requires_configured_provider(monkeypatch):
    import api.main as main
    monkeypatch.setattr(main, 'llm_status', lambda: {'llm_configured': False})
    client = TestClient(app)
    response = client.post('/api/redteam/live', json={'attack_types':['instruction_override']})
    assert response.status_code == 409
