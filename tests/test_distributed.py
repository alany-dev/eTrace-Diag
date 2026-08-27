"""Distributed edge agent + coordinator tests (HTTP/JSON-replay reproducible).

Covers: Model 1 only on the edge (summary messages, never raw series),
clock-offset correction before propagation-order comparison, bandwidth
estimate under the 16 KB/s budget, and coordinator joint analysis fallback
('not jointly identified') when J-PCMCIplus cannot run.
"""

from __future__ import annotations

import json

from alg_models.cli import split_by_time
from alg_models.data.replay import load_replay
from alg_models.distributed.agent import AgentMessage, EdgeAgent
from alg_models.distributed.coordinator import Coordinator


def test_agent_emits_summary_only():
    frame = load_replay("tests/fixtures/host_spike.jsonl")
    train, val, _ = split_by_time(frame, 0.6, 0.2)
    agent = EdgeAgent("host-a", "cluster-1", clock_offset_ns=5_000_000_000,
                      config={"detector": {"name": "streaming",
                                           "window_ns": 60_000_000_000,
                                           "stride_ns": 30_000_000_000}})
    agent.fit(train, val, seed=7)
    msgs = agent.process(frame)
    assert msgs, "agent must report at least one incident summary"
    m = msgs[0]
    # summary messages never carry raw series
    assert m.incident.metric_scores and "points" not in m.to_dict()
    assert m.cluster_id == "cluster-1"
    assert m.host_id == "host-a"
    assert m.schema_version == EdgeAgent.SCHEMA_VERSION
    assert m.model_version
    assert m.incident_id


def test_agent_message_roundtrip():
    frame = load_replay("tests/fixtures/host_spike.jsonl")
    train, val, _ = split_by_time(frame, 0.6, 0.2)
    agent = EdgeAgent("host-a", "c1", config={"detector": {"name": "streaming"}})
    agent.fit(train, val, seed=7)
    msg = agent.process(frame)[0]
    revived = AgentMessage.from_dict(json.loads(json.dumps(msg.to_dict())))
    assert revived.incident_id == msg.incident_id
    assert revived.clock_offset_ns == msg.clock_offset_ns


def test_coordinator_clock_correction_and_order():
    frame = load_replay("tests/fixtures/causal_disk_chain.jsonl")
    train, val, _ = split_by_time(frame, 0.6, 0.2)
    # two hosts with different clock offsets, same incident
    a = EdgeAgent("host-a", "c1", clock_offset_ns=0,
                  config={"detector": {"name": "streaming"}})
    b = EdgeAgent("host-b", "c1", clock_offset_ns=30_000_000_000,
                  config={"detector": {"name": "streaming"}})
    a.fit(train, val, seed=7)
    b.fit(train, val, seed=7)
    coord = Coordinator("c1")
    for m in a.process(frame)[:1] + b.process(frame)[:1]:
        coord.ingest(m)
    order = coord.propagation_order()
    assert order == ["host-a", "host-b"]  # b's clock is ahead by 30 s
    # bandwidth: summary-only reporting stays tiny
    byt = a.estimate_bandwidth_bytes(a.process(frame)[:1])
    assert byt < 16 * 1024, "summary reporting exceeds 16 KB/s-node budget"


def test_coordinator_joint_analysis_falls_back_gracefully():
    frame = load_replay("tests/fixtures/causal_disk_chain.jsonl")
    train, val, _ = split_by_time(frame, 0.6, 0.2)
    a = EdgeAgent("host-a", "c1", config={"detector": {"name": "streaming"}})
    a.fit(train, val, seed=7)
    coord = Coordinator("c1", use_jpcmciplus=True)
    for m in a.process(frame)[:1]:
        coord.ingest(m)
    report = coord.analyze({"host-a": frame}, top_k=3, seed=7)
    # explicit 'not jointly identified' limitation, no fabricated joint graph
    assert any("not jointly identified" in l for l in report.limitations)
    assert report.incident_id


def test_agent_rejects_wrong_cluster():
    coord = Coordinator("c1")
    msg = AgentMessage(
        message_id="m1", cluster_id="other", host_id="h",
        clock_offset_ns=0, schema_version="1.0.0", model_version="0.1.0",
        incident_id="inc", incident=__import__(
            "alg_models.schemas", fromlist=["IncidentWindow"]
        ).IncidentWindow(
            incident_id="inc", start_ts_ns=0, end_ts_ns=10,
            detected_at_ns=5, status="anomaly", severity=0.5,
        ),
        quality_summary={},
    )
    try:
        coord.ingest(msg)
        raise AssertionError("ingest must reject a foreign cluster message")
    except ValueError:
        pass