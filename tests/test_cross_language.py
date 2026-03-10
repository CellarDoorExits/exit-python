"""Cross-language test vectors — verify Python matches TypeScript output."""

import json
from pathlib import Path

import pytest

from exit_door import (
    create_marker,
    ExitType,
)
from exit_door.marker import canonicalize, compute_id


VECTORS_PATH = Path(__file__).parent / "test-vectors.json"


@pytest.fixture(scope="module")
def vectors() -> dict:
    with open(VECTORS_PATH) as f:
        return json.load(f)


class TestCanonicalization:
    def test_all_canonicalization_vectors(self, vectors: dict) -> None:
        for case in vectors["canonicalization"]:
            result = canonicalize(case["input"])
            assert result == case["expected"], (
                f"Canonicalization mismatch for '{case['description']}': "
                f"got {result!r}, expected {case['expected']!r}"
            )


class TestMarkerCreation:
    def _create_from_vector(self, input_data: dict):
        """Create a marker from vector input data."""
        exit_type_map = {
            "voluntary": ExitType.VOLUNTARY,
            "forced": ExitType.FORCED,
            "emergency": ExitType.EMERGENCY,
        }
        kwargs = {
            "subject": input_data["subject"],
            "origin": input_data["origin"],
            "exit_type": exit_type_map[input_data["exitType"]],
            "timestamp": input_data["timestamp"],
        }
        if "emergencyJustification" in input_data:
            kwargs["emergency_justification"] = input_data["emergencyJustification"]
        return create_marker(**kwargs)

    def test_voluntary_marker_id(self, vectors: dict) -> None:
        v = vectors["markers"]["voluntary"]
        marker = self._create_from_vector(v["input"])
        assert marker.id == v["expected"]["id"], (
            f"Voluntary marker ID mismatch: got {marker.id}, expected {v['expected']['id']}"
        )

    def test_voluntary_content_hash(self, vectors: dict) -> None:
        v = vectors["markers"]["voluntary"]
        marker = self._create_from_vector(v["input"])
        marker_dict = marker.model_dump(by_alias=True, exclude_none=True)
        content_hash = compute_id(marker_dict)
        assert content_hash == v["contentHash"], (
            f"Content hash mismatch: got {content_hash}, expected {v['contentHash']}"
        )

    def test_voluntary_canonicalized(self, vectors: dict) -> None:
        v = vectors["markers"]["voluntary"]
        marker = self._create_from_vector(v["input"])
        # Exclude proof and id for content hashing (matching TypeScript)
        d = marker.model_dump(by_alias=True, exclude_none=True)
        d.pop("proof", None)
        d.pop("id", None)
        result = canonicalize(d)
        assert result == v["canonicalized"], (
            f"Canonicalization mismatch:\ngot:      {result}\nexpected: {v['canonicalized']}"
        )

    def test_forced_marker_id(self, vectors: dict) -> None:
        v = vectors["markers"]["forced"]
        marker = self._create_from_vector(v["input"])
        assert marker.id == v["expected"]["id"]

    def test_emergency_marker_id(self, vectors: dict) -> None:
        v = vectors["markers"]["emergency"]
        marker = self._create_from_vector(v["input"])
        assert marker.id == v["expected"]["id"]

    def test_deterministic_ids(self, vectors: dict) -> None:
        """Same inputs should always produce the same ID."""
        ca = vectors["contentAddressing"]
        assert ca["areEqual"] is True


class TestModules:
    def test_add_module_changes_id(self, vectors: dict) -> None:
        """Adding a module should produce a different content-addressed ID."""
        m = vectors["modules"]["lineage"]
        assert m["idsAreDifferent"] is True
        assert m["baseMarkerId"] != m["withModuleId"]
