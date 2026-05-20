"""End-to-end sub-client tests with mocked HTTP via the ``responses`` lib.

These exercise the full path from the wrapper through FalconPy to the
``requests`` layer, which proves that the OAuth flow and our retry
shim cooperate with FalconPy's response shape on a real (mocked)
HTTP round trip.
"""

from __future__ import annotations

from typing import Any

import pytest
import responses

from csfwctl.config import Credentials
from csfwctl.falcon.client import FalconClient

BASE = "https://api.crowdstrike.com"
TOKEN_URL = f"{BASE}/oauth2/token"


@pytest.fixture
def mocked_api() -> Any:
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(
            responses.POST,
            TOKEN_URL,
            json={"access_token": "fake-token", "expires_in": 1800},
            status=201,
        )
        yield rsps


def _client() -> FalconClient:
    creds = Credentials(
        client_id="cid",
        client_secret="secret",
        base_url=BASE,
        profile="test",
        source="test",
    )
    return FalconClient(creds, base_backoff_seconds=0.0, sleep=lambda _s: None)


def test_policies_list_all_round_trips(mocked_api: responses.RequestsMock) -> None:
    mocked_api.add(
        responses.GET,
        f"{BASE}/policy/queries/firewall/v1",
        json={
            "resources": ["pol-1", "pol-2"],
            "errors": [],
            "meta": {"pagination": {"total": 2}},
        },
        status=200,
    )
    mocked_api.add(
        responses.GET,
        f"{BASE}/policy/entities/firewall/v1",
        json={
            "resources": [
                {"id": "pol-1", "name": "Endpoints-Windows-Test"},
                {"id": "pol-2", "name": "Endpoints-Windows-Pilot"},
            ],
            "errors": [],
        },
        status=200,
    )
    client = _client()
    policies = client.policies.list_all()
    assert [p["id"] for p in policies] == ["pol-1", "pol-2"]


def test_rule_groups_query_returns_ids(mocked_api: responses.RequestsMock) -> None:
    mocked_api.add(
        responses.GET,
        f"{BASE}/fwmgr/queries/rule-groups/v1",
        json={"resources": ["rg-1"], "errors": []},
        status=200,
    )
    client = _client()
    ids = client.rule_groups.query(filter="platform:'windows'")
    assert ids == ["rg-1"]


def test_host_groups_find_by_name(mocked_api: responses.RequestsMock) -> None:
    mocked_api.add(
        responses.GET,
        f"{BASE}/devices/queries/host-groups/v1",
        json={"resources": ["hg-1"], "errors": []},
        status=200,
    )
    mocked_api.add(
        responses.GET,
        f"{BASE}/devices/entities/host-groups/v1",
        json={
            "resources": [{"id": "hg-1", "name": "ABC01-Endpoints-Windows-Test"}],
            "errors": [],
        },
        status=200,
    )
    client = _client()
    group = client.host_groups.find_by_name("ABC01-Endpoints-Windows-Test")
    assert group is not None
    assert group["id"] == "hg-1"


def test_locations_list_all_calls_details_endpoint(mocked_api: responses.RequestsMock) -> None:
    mocked_api.add(
        responses.GET,
        f"{BASE}/fwmgr/queries/network-locations/v1",
        json={"resources": ["loc-1"], "errors": []},
        status=200,
    )
    mocked_api.add(
        responses.GET,
        f"{BASE}/fwmgr/entities/network-locations-details/v1",
        json={
            "resources": [
                {
                    "id": "loc-1",
                    "name": "corp-vpn",
                    "addresses": [{"address": "10.100.0.0/16"}],
                }
            ],
            "errors": [],
        },
        status=200,
    )
    client = _client()
    locs = client.locations.list_all()
    assert locs[0]["name"] == "corp-vpn"


def test_retry_path_with_http(mocked_api: responses.RequestsMock) -> None:
    mocked_api.add(
        responses.GET,
        f"{BASE}/policy/queries/firewall/v1",
        json={"errors": [{"message": "rate limited"}]},
        status=429,
        headers={"Retry-After": "0"},
    )
    mocked_api.add(
        responses.GET,
        f"{BASE}/policy/queries/firewall/v1",
        json={"resources": ["pol-1"], "errors": []},
        status=200,
    )
    client = _client()
    ids = client.policies.query()
    assert ids == ["pol-1"]
