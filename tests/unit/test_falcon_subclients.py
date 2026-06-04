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


def test_rule_groups_query_sends_limit_5000_by_default(mocked_api: responses.RequestsMock) -> None:
    """query() without an explicit limit must request 5 000 results to avoid the API default of 10."""
    import urllib.parse

    captured_urls: list[str] = []

    def capture_request(request: Any) -> Any:  # type: ignore[type-arg]
        captured_urls.append(request.url)
        return (200, {}, '{"resources": ["rg-1"], "errors": []}')

    mocked_api.add_callback(responses.GET, f"{BASE}/fwmgr/queries/rule-groups/v1", capture_request)
    client = _client()
    client.rule_groups.query()

    assert captured_urls, "no request was made"
    parsed = urllib.parse.urlparse(captured_urls[0])
    params = urllib.parse.parse_qs(parsed.query)
    assert params.get("limit") == ["5000"]


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


def test_host_groups_find_by_name_falls_back_to_list_all(
    mocked_api: responses.RequestsMock,
) -> None:
    """When the FQL ``name:`` filter returns empty, ``find_by_name`` lists
    every host group and matches by exact name client-side.

    Regression: some CrowdStrike tenants have been observed returning
    empty resources for the ``name:`` filter even when an exact-match
    group exists. The applier then issued ``create`` and the server
    rejected it with ``409 Duplicate group name``.
    """
    # First call: filtered query returns no results.
    mocked_api.add(
        responses.GET,
        f"{BASE}/devices/queries/host-groups/v1",
        json={"resources": [], "errors": []},
        status=200,
    )
    # Second call (fallback): unfiltered query returns several IDs.
    mocked_api.add(
        responses.GET,
        f"{BASE}/devices/queries/host-groups/v1",
        json={"resources": ["hg-1", "hg-2", "hg-3"], "errors": []},
        status=200,
    )
    mocked_api.add(
        responses.GET,
        f"{BASE}/devices/entities/host-groups/v1",
        json={
            "resources": [
                {"id": "hg-1", "name": "Other-Group"},
                {"id": "hg-2", "name": "OSU-ASC-Endpoints-Windows-Pilot"},
                {"id": "hg-3", "name": "Yet-Another"},
            ],
            "errors": [],
        },
        status=200,
    )
    client = _client()
    group = client.host_groups.find_by_name("OSU-ASC-Endpoints-Windows-Pilot")
    assert group is not None
    assert group["id"] == "hg-2"


def test_host_groups_create_returns_existing_on_duplicate_409(
    mocked_api: responses.RequestsMock,
) -> None:
    """``create`` is idempotent on the duplicate-name 409.

    The applier calls ``create`` when ``find_by_name`` returns ``None``.
    If the FQL filter falsely reported the group as absent but the
    server actually has it, the create returns 409. The wrapper falls
    back to a thorough lookup and returns the existing record, so the
    applier can use the live id instead of aborting the apply.
    """
    duplicate_body = {
        "errors": [
            {"code": 409, "message": "Duplicate group name OSU-ASC-Endpoints-Windows-Pilot."}
        ],
        "resources": None,
    }
    mocked_api.add(
        responses.POST,
        f"{BASE}/devices/entities/host-groups/v1",
        json=duplicate_body,
        status=409,
    )
    # Fallback lookup: name filter still returns empty (the original
    # reason the create was attempted), then list_all returns the group.
    mocked_api.add(
        responses.GET,
        f"{BASE}/devices/queries/host-groups/v1",
        json={"resources": [], "errors": []},
        status=200,
    )
    mocked_api.add(
        responses.GET,
        f"{BASE}/devices/queries/host-groups/v1",
        json={"resources": ["hg-9"], "errors": []},
        status=200,
    )
    mocked_api.add(
        responses.GET,
        f"{BASE}/devices/entities/host-groups/v1",
        json={
            "resources": [{"id": "hg-9", "name": "OSU-ASC-Endpoints-Windows-Pilot"}],
            "errors": [],
        },
        status=200,
    )
    client = _client()
    created = client.host_groups.create("OSU-ASC-Endpoints-Windows-Pilot")
    assert created.get("id") == "hg-9"
    assert created.get("name") == "OSU-ASC-Endpoints-Windows-Pilot"


def test_host_groups_query_sends_limit_500_by_default(
    mocked_api: responses.RequestsMock,
) -> None:
    """The host-groups endpoint caps ``limit`` at 500 (HTTP 400 otherwise).

    Regression: the default page size was previously 5 000, which the
    server rejected with ``"5000 is an invalid page size, must be
    between 1 and 500"``, breaking ``apply`` on every fetch of live
    state.
    """
    import urllib.parse

    captured_urls: list[str] = []

    def _record(request: Any) -> tuple[int, dict[str, str], str]:
        captured_urls.append(request.url)
        return (200, {}, '{"resources": [], "errors": []}')

    mocked_api.add_callback(
        responses.GET,
        f"{BASE}/devices/queries/host-groups/v1",
        callback=_record,
    )
    client = _client()
    client.host_groups.query()
    assert captured_urls, "no request was made"
    parsed = urllib.parse.urlparse(captured_urls[0])
    params = urllib.parse.parse_qs(parsed.query)
    assert params.get("limit") == ["500"]


def test_host_groups_query_paginates_to_collect_all_ids(
    mocked_api: responses.RequestsMock,
) -> None:
    """Without an explicit ``limit``, ``query`` paginates through all pages.

    A tenant with more than 500 host groups was previously truncated
    silently by the API page-size cap, which made the unfiltered
    fallback in ``find_by_name`` miss exactly the record it was trying
    to locate. The query must walk offset-based pages until the API
    reports it has returned ``total`` results (or returns a short
    page).
    """
    page_one = [f"hg-{i}" for i in range(500)]
    page_two = [f"hg-{i}" for i in range(500, 750)]
    mocked_api.add(
        responses.GET,
        f"{BASE}/devices/queries/host-groups/v1",
        json={
            "resources": page_one,
            "errors": [],
            "meta": {"pagination": {"offset": 0, "limit": 500, "total": 750}},
        },
        status=200,
    )
    mocked_api.add(
        responses.GET,
        f"{BASE}/devices/queries/host-groups/v1",
        json={
            "resources": page_two,
            "errors": [],
            "meta": {"pagination": {"offset": 500, "limit": 500, "total": 750}},
        },
        status=200,
    )
    client = _client()
    ids = client.host_groups.query()
    assert len(ids) == 750
    assert ids[0] == "hg-0"
    assert ids[-1] == "hg-749"


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


def test_policies_get_policy_containers(mocked_api: responses.RequestsMock) -> None:
    mocked_api.add(
        responses.GET,
        f"{BASE}/fwmgr/entities/policies/v1",
        json={
            "resources": [
                {"policy_id": "pol-1", "rule_group_ids": ["rg-a", "rg-b"]},
            ],
            "errors": [],
        },
        status=200,
    )
    client = _client()
    containers = client.policies.get_policy_containers(["pol-1"])
    assert len(containers) == 1
    assert containers[0]["policy_id"] == "pol-1"
    assert containers[0]["rule_group_ids"] == ["rg-a", "rg-b"]


def test_policies_get_policy_containers_empty_ids(mocked_api: responses.RequestsMock) -> None:
    client = _client()
    result = client.policies.get_policy_containers([])
    assert result == []


def test_rule_groups_update_returns_id_from_string_resource(
    mocked_api: responses.RequestsMock,
) -> None:
    """The update endpoint returns ``resources`` as bare ID strings.

    Regression for a ``dict(resources[0])`` ValueError when the API
    returns ``{"resources": ["<id>"]}`` rather than full objects.
    """
    mocked_api.add(
        responses.PATCH,
        f"{BASE}/fwmgr/entities/rule-groups/v1",
        json={"resources": ["rg-123"], "errors": []},
        status=200,
    )
    client = _client()
    result = client.rule_groups.update({"id": "rg-123", "diff_operations": []})
    assert result == {"id": "rg-123"}


def test_rule_groups_create_returns_id_from_string_resource(
    mocked_api: responses.RequestsMock,
) -> None:
    """Create likewise returns a bare ID string in ``resources``."""
    mocked_api.add(
        responses.POST,
        f"{BASE}/fwmgr/entities/rule-groups/v1",
        json={"resources": ["rg-new"], "errors": []},
        status=201,
    )
    client = _client()
    result = client.rule_groups.create({"name": "win", "platform": "Windows"})
    assert result == {"id": "rg-new"}


def test_rule_groups_update_passes_through_dict_resource(
    mocked_api: responses.RequestsMock,
) -> None:
    """A dict resource (some endpoints/mocks return one) is passed through."""
    mocked_api.add(
        responses.PATCH,
        f"{BASE}/fwmgr/entities/rule-groups/v1",
        json={"resources": [{"id": "rg-9", "name": "win"}], "errors": []},
        status=200,
    )
    client = _client()
    result = client.rule_groups.update({"id": "rg-9"})
    assert result == {"id": "rg-9", "name": "win"}


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
