"""Live rule-group round-trip against a real CrowdStrike test tenant.

This is the one test that is **not** hermetic: it provisions a throwaway
rule group in a real Falcon tenant and exercises the create -> update
(add / modify / remove rules) -> re-fetch -> assert -> delete cycle.  Its
purpose is to confirm the parts of the wire contract that mocks cannot —
chiefly the ``image_name`` filepath field shape and the diff-based
``update_rule_group`` payload built by
:func:`csfwctl.applier._build_rule_group_update_payload`.

It is opt-in and gated three ways so it can never run in the normal suite:

- marked ``live`` (the marker is registered in ``pyproject.toml``);
- skipped unless ``CSFWCTL_LIVE_TEST=1``;
- requires real credentials resolvable by :func:`load_credentials`.

Everything it creates is namespaced ``csfwctl-live-*`` and deleted in a
``finally`` block, so a failure never leaves managed config behind.  Run it
with::

    CSFWCTL_LIVE_TEST=1 pytest -m live tests/integration/test_live_rule_group.py
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import pytest

from csfwctl.applier import ApplyOptions, _build_rule_group_update_payload
from csfwctl.config import load_credentials
from csfwctl.differ import DiffOp, FieldChange, ManagedStatus, ObjectChange
from csfwctl.exporter import rule_group_from_api, rule_group_to_api_shape
from csfwctl.falcon.client import FalconClient
from csfwctl.schema import (
    Action,
    Direction,
    Endpoint,
    Platform,
    Protocol,
    Rule,
    RuleGroup,
)

LIVE_ENABLED = os.getenv("CSFWCTL_LIVE_TEST") == "1"

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not LIVE_ENABLED,
        reason="live tenant test: set CSFWCTL_LIVE_TEST=1 and provide credentials to run",
    ),
]

# The test tenant is mac-platform for ASC; override via env if needed. The
# filepath ``type`` token follows the platform (unix_path vs windows_path).
_PLATFORM = Platform(os.getenv("CSFWCTL_LIVE_PLATFORM", "mac"))
_FILE_PATH = "/usr/libexec/rapportd" if _PLATFORM is Platform.mac else r"C:\Program Files\app\*.exe"


def _client() -> FalconClient:
    creds = load_credentials(os.getenv("CSFWCTL_LIVE_PROFILE") or "env")
    return FalconClient(creds)


def _fetch(client: FalconClient, rg_id: str) -> tuple[dict[str, Any], RuleGroup]:
    """Return the live rule-group record plus the reconstructed model."""
    records = client.rule_groups.get([rg_id])
    assert records, f"rule group {rg_id} not found after write"
    record = records[0]
    rule_ids = [str(r) for r in record.get("rule_ids") or []]
    rules = client.rule_groups.get_rules(rule_ids) if rule_ids else []
    rules_by_id: dict[str, dict[str, Any]] = {}
    for rule in rules:
        rules_by_id[str(rule.get("id"))] = rule
        fam = rule.get("family_id")
        if fam:
            rules_by_id[str(fam)] = rule
    return record, rule_group_from_api(record, rules_by_id)


def _rules_change(live: RuleGroup, desired: RuleGroup) -> ObjectChange:
    """Build the ObjectChange the applier consumes (the differ produces the same)."""
    return ObjectChange(
        kind="rule-group",
        op=DiffOp.update,
        slug=desired.name,
        display_name=desired.display_name or desired.name,
        managed=ManagedStatus.managed,
        field_changes=(
            FieldChange(
                path="rules",
                before=[r.model_dump() for r in live.rules],
                after=[r.model_dump() for r in desired.rules],
            ),
        ),
    )


def _apply_update(
    client: FalconClient,
    options: ApplyOptions,
    rg_id: str,
    record: dict[str, Any],
    live: RuleGroup,
    desired: RuleGroup,
) -> None:
    payload = _build_rule_group_update_payload(
        desired,
        options,
        live_id=rg_id,
        live_description=record.get("description"),
        live_record=record,
        change=_rules_change(live, desired),
    )
    client.rule_groups.update(payload)


def test_live_rule_group_add_modify_remove_round_trip() -> None:
    """Provision a throwaway rule group and confirm the diff-based update path."""
    client = _client()
    options = ApplyOptions(env="test", git_sha="live-validation")
    suffix = uuid.uuid4().hex[:8]

    keep = Rule(
        name="keep-me",
        action=Action.allow,
        direction=Direction.outbound,
        protocol=Protocol.tcp,
        file_path=_FILE_PATH,
        remote=Endpoint(ports=[443]),
    )
    rg_v1 = RuleGroup(
        name=f"csfwctl-live-{suffix}",
        platform=_PLATFORM,
        description="csfwctl live validation — safe to delete.",
        rules=[keep],
    )

    rg_id: str | None = None
    try:
        # ---- create -------------------------------------------------------
        create_payload = rule_group_to_api_shape(rg_v1, options.env)
        create_payload.pop("id", None)
        created = client.rule_groups.create(create_payload)
        rg_id = str(created.get("id") or "")
        assert rg_id, f"create returned no id: {created!r}"

        record, live = _fetch(client, rg_id)
        # The filepath must survive as an image_name field on the live rule.
        assert live.rules[0].file_path == _FILE_PATH, (
            "image_name filepath did not round-trip through create"
        )

        # ---- update: ADD a second rule -----------------------------------
        added = Rule(
            name="added-rule",
            action=Action.allow,
            direction=Direction.inbound,
            protocol=Protocol.tcp,
            local=Endpoint(ports=[8443]),
        )
        rg_v2 = rg_v1.model_copy(update={"rules": [keep, added]})
        _apply_update(client, options, rg_id, record, live, rg_v2)

        record, live = _fetch(client, rg_id)
        names = {r.name for r in live.rules}
        assert names == {"keep-me", "added-rule"}, f"add op did not persist: {names}"

        # ---- update: MODIFY the kept rule (block instead of allow) --------
        modified_keep = keep.model_copy(update={"action": Action.block})
        rg_v3 = rg_v2.model_copy(update={"rules": [modified_keep, added]})
        _apply_update(client, options, rg_id, record, live, rg_v3)

        record, live = _fetch(client, rg_id)
        by_name = {r.name: r for r in live.rules}
        assert by_name["keep-me"].action is Action.block, "modify op did not persist"

        # ---- update: REMOVE the added rule -------------------------------
        rg_v4 = rg_v3.model_copy(update={"rules": [modified_keep]})
        _apply_update(client, options, rg_id, record, live, rg_v4)

        record, live = _fetch(client, rg_id)
        names = {r.name for r in live.rules}
        assert names == {"keep-me"}, f"remove op did not persist: {names}"
    finally:
        if rg_id:
            client.rule_groups.delete([rg_id])
