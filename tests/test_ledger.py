"""Tests for the tamper-proof ledger — the most critical component."""

import copy
import json
import tempfile
from pathlib import Path

import pytest

from agent_comply.ledger import EventLedger, LedgerEvent, MerkleTree, _sha256


# ── Basic append & chain ──────────────────────────────────────────────
class TestEventLedger:
    def test_append_single_event(self):
        ledger = EventLedger()
        ev = ledger.append({"action": "search", "query": "test"})
        assert ev.sequence == 0
        assert ev.event_hash != ""
        assert ev.payload_hash != ""
        assert len(ledger) == 1

    def test_append_multiple_events(self):
        ledger = EventLedger()
        ev1 = ledger.append({"step": 1})
        ev2 = ledger.append({"step": 2})
        ev3 = ledger.append({"step": 3})
        assert ev1.sequence == 0
        assert ev2.sequence == 1
        assert ev3.sequence == 2
        assert len(ledger) == 3

    def test_hash_chain_links(self):
        ledger = EventLedger()
        ev1 = ledger.append({"a": 1})
        ev2 = ledger.append({"b": 2})
        ev3 = ledger.append({"c": 3})
        # Each event's previous_hash == prior event's event_hash
        assert ev2.previous_hash == ev1.event_hash
        assert ev3.previous_hash == ev2.event_hash

    def test_genesis_hash(self):
        ledger = EventLedger()
        ev = ledger.append({"first": True})
        assert ev.previous_hash == _sha256("GENESIS")

    def test_event_hash_is_deterministic(self):
        ledger = EventLedger()
        ev = ledger.append({"x": 42})
        assert ev.event_hash == ev.compute_hash()


# ── Integrity verification ────────────────────────────────────────────
class TestChainVerification:
    def _build_ledger(self, n: int = 10) -> EventLedger:
        ledger = EventLedger()
        for i in range(n):
            ledger.append({"step": i, "data": f"value-{i}"})
        return ledger

    def test_valid_chain_passes(self):
        ledger = self._build_ledger()
        ok, errors = ledger.verify_chain()
        assert ok is True
        assert errors == []

    def test_tampered_payload_detected(self):
        ledger = self._build_ledger()
        # Tamper with payload of event 5
        ledger._events[5].payload["step"] = 999
        ok, errors = ledger.verify_chain()
        assert ok is False
        assert any("payload_hash" in e for e in errors)

    def test_tampered_event_hash_detected(self):
        ledger = self._build_ledger()
        ledger._events[3].event_hash = "deadbeef" * 8
        ok, errors = ledger.verify_chain()
        assert ok is False
        assert len(errors) >= 1

    def test_tampered_previous_hash_detected(self):
        ledger = self._build_ledger()
        ledger._events[4].previous_hash = "0" * 64
        ok, errors = ledger.verify_chain()
        assert ok is False

    def test_deleted_event_detected(self):
        ledger = self._build_ledger()
        # Remove event 5 — breaks the chain
        del ledger._events[5]
        ok, errors = ledger.verify_chain()
        assert ok is False

    def test_reordered_events_detected(self):
        ledger = self._build_ledger()
        ledger._events[2], ledger._events[3] = ledger._events[3], ledger._events[2]
        ok, errors = ledger.verify_chain()
        assert ok is False

    def test_inserted_event_detected(self):
        ledger = self._build_ledger(5)
        # Forge a fake event and insert it
        fake = LedgerEvent(
            event_id="EVT-fake",
            sequence=2,
            payload={"fake": True},
            payload_hash=_sha256(json.dumps({"fake": True}, sort_keys=True)),
            previous_hash=ledger._events[1].event_hash,
        )
        fake.event_hash = fake.compute_hash()
        ledger._events.insert(2, fake)
        ok, errors = ledger.verify_chain()
        # Event 3 (formerly 2) now has wrong previous_hash
        assert ok is False


# ── Merkle tree ───────────────────────────────────────────────────────
class TestMerkleTree:
    def test_empty_tree(self):
        t = MerkleTree()
        assert t.root == _sha256("")
        assert t.leaf_count == 0

    def test_single_leaf(self):
        t = MerkleTree()
        t.add_leaf("abc123")
        assert t.leaf_count == 1
        assert t.root != ""

    def test_proof_single_leaf(self):
        t = MerkleTree()
        t.add_leaf("abc123")
        proof = t.get_proof(0)
        assert t.verify_proof("abc123", 0, proof) is True

    def test_proof_multiple_leaves(self):
        t = MerkleTree()
        leaves = [_sha256(f"leaf-{i}") for i in range(8)]
        for lf in leaves:
            t.add_leaf(lf)
        for i, lf in enumerate(leaves):
            proof = t.get_proof(i)
            assert t.verify_proof(lf, i, proof) is True

    def test_tampered_leaf_fails_proof(self):
        t = MerkleTree()
        leaves = [_sha256(f"leaf-{i}") for i in range(4)]
        for lf in leaves:
            t.add_leaf(lf)
        proof = t.get_proof(2)
        # Tamper: use wrong hash
        assert t.verify_proof("tampered", 2, proof) is False

    def test_root_changes_with_new_leaf(self):
        t = MerkleTree()
        t.add_leaf("a")
        root1 = t.root
        t.add_leaf("b")
        root2 = t.root
        assert root1 != root2

    def test_non_power_of_two_leaves(self):
        t = MerkleTree()
        for i in range(7):
            t.add_leaf(_sha256(str(i)))
        for i in range(7):
            proof = t.get_proof(i)
            assert t.verify_proof(_sha256(str(i)), i, proof) is True

    def test_proof_index_out_of_range(self):
        t = MerkleTree()
        t.add_leaf("x")
        with pytest.raises(IndexError):
            t.get_proof(5)


# ── Full verification (chain + Merkle) ────────────────────────────────
class TestFullVerification:
    def test_verify_all_passes_clean_ledger(self):
        ledger = EventLedger()
        for i in range(20):
            ledger.append({"i": i})
        ok, errors = ledger.verify_all()
        assert ok is True
        assert errors == []

    def test_verify_merkle_individual_events(self):
        ledger = EventLedger()
        for i in range(10):
            ledger.append({"i": i})
        for i in range(10):
            assert ledger.verify_merkle(i) is True


# ── Serialisation roundtrip ───────────────────────────────────────────
class TestSerialisation:
    def test_jsonl_roundtrip(self, tmp_path: Path):
        ledger = EventLedger()
        for i in range(5):
            ledger.append({"step": i})

        path = tmp_path / "events.jsonl"
        ledger.export_jsonl(path)
        loaded = EventLedger.import_jsonl(path)

        assert len(loaded) == 5
        ok, errors = loaded.verify_chain()
        assert ok is True

    def test_jsonl_roundtrip_preserves_hashes(self, tmp_path: Path):
        ledger = EventLedger()
        for i in range(3):
            ledger.append({"v": i})
        path = tmp_path / "out.jsonl"
        ledger.export_jsonl(path)
        loaded = EventLedger.import_jsonl(path)

        for orig, loaded_ev in zip(ledger.events, loaded.events):
            assert orig.event_hash == loaded_ev.event_hash
            assert orig.previous_hash == loaded_ev.previous_hash
