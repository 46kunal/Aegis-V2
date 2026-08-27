from types import SimpleNamespace
from uuid import UUID

import networkx as nx

from app.models.finding import Finding, FindingSeverity
from app.services import attack_engine


OWNER_ID = "33333333-3333-3333-3333-333333333333"
KALI_ID = UUID("10000000-0000-0000-0000-000000000001")
LINUX_ID = UUID("10000000-0000-0000-0000-000000000002")
WINDOWS_ID = UUID("10000000-0000-0000-0000-000000000003")
PRINTER_ID = UUID("10000000-0000-0000-0000-000000000004")


class FakeQuery:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *_, **__):
        return self

    def all(self):
        return self.rows


class FakeDatabase:
    def __init__(self, findings):
        self.findings = findings

    def query(self, model):
        assert model is Finding
        return FakeQuery(self.findings)


def asset(asset_id, name, ip, criticality="medium", exposure="internal", risk_score=10.0):
    return SimpleNamespace(
        id=asset_id,
        name=name,
        target=ip,
        ip_address=ip,
        criticality=criticality,
        exposure=exposure,
        risk_score=risk_score,
    )


def finding(
    asset_id,
    port,
    cve_id,
    service,
    product=None,
    version=None,
    cvss=7.5,
    epss=0.2,
    kev=False,
    severity=FindingSeverity.HIGH,
):
    return SimpleNamespace(
        asset_id=asset_id,
        port=port,
        protocol="tcp",
        cve_id=cve_id,
        cwe_id=None,
        cvss_score=cvss,
        cvss_vector=None,
        epss_score=epss,
        is_kev=kev,
        severity=severity,
        normalized_service=service,
        raw_service=service,
        detected_product=product,
        detected_version=version,
        extracted_version=version,
        title=f"{cve_id or service} finding",
    )


def graph_for(assets, edges):
    graph = nx.DiGraph()
    for current in assets:
        graph.add_node(str(current.id))
    for source, target, relationship, label, exploitability, technique_id, technique_name in edges:
        graph.add_edge(
            str(source),
            str(target),
            relationship=relationship,
            label=label,
            exploitability=exploitability,
            inv_weight=1 / exploitability,
            technique_id=technique_id,
            technique_name=technique_name,
            weight=exploitability,
            meta={},
        )
    return graph


def test_simulation_builds_explainable_cve_backed_lateral_chain(monkeypatch):
    kali = asset(KALI_ID, "Kali", "192.168.56.10", risk_score=20)
    linux = asset(LINUX_ID, "Metasploitable", "192.168.56.20", risk_score=85)
    windows = asset(WINDOWS_ID, "Windows Host", "192.168.56.30", criticality="critical", exposure="external", risk_score=92)
    assets = [kali, linux, windows]
    asset_map = {str(current.id): current for current in assets}
    graph = graph_for(
        assets,
        [
            (
                KALI_ID,
                LINUX_ID,
                "shares_files",
                "file sharing service on port 21",
                9.4,
                "T1021.002",
                "Remote Services: SMB/Admin Shares",
            ),
            (
                LINUX_ID,
                WINDOWS_ID,
                "shares_files",
                "file sharing service on port 445",
                8.7,
                "T1021.002",
                "Remote Services: SMB/Admin Shares",
            ),
        ],
    )
    findings = [
        finding(
            LINUX_ID,
            21,
            "CVE-2011-2523",
            "ftp",
            product="vsFTPd",
            version="2.3.4",
            cvss=10.0,
            epss=0.84,
            kev=True,
            severity=FindingSeverity.CRITICAL,
        ),
        finding(
            WINDOWS_ID,
            445,
            "CVE-2017-0144",
            "smb",
            product="Microsoft SMB",
            version="1.0",
            cvss=9.3,
            epss=0.73,
            kev=True,
            severity=FindingSeverity.CRITICAL,
        ),
    ]

    monkeypatch.setattr(attack_engine, "_load_graph", lambda *_: (graph, assets, asset_map))

    result = attack_engine.simulate_from(
        database=FakeDatabase(findings),
        owner_id=OWNER_ID,
        source_id=str(KALI_ID),
        limit=5,
    )

    assert result["blast_radius_count"] == 2
    assert result["blast_radius_critical_count"] == 1
    assert result["attack_chains"]

    windows_chain = next(chain for chain in result["attack_chains"] if chain["target_id"] == str(WINDOWS_ID))
    progression_labels = [node["label"] for node in windows_chain["progression"]]
    assert "CVE-2011-2523" in progression_labels
    assert "vsFTPd 2.3.4" in progression_labels
    assert "CVE-2017-0144" in progression_labels
    assert windows_chain["feasibility"] == "EASY"
    assert windows_chain["risk_score"] > 75
    assert "Lateral Movement" in windows_chain["stage_sequence"]
    assert any(stage["technique_id"].startswith("T") for stage in windows_chain["stage_details"])


def test_simulation_rejects_generic_reachability_without_exploit_context(monkeypatch):
    kali = asset(KALI_ID, "Kali", "192.168.56.10")
    printer = asset(PRINTER_ID, "Printer", "192.168.56.40", risk_score=55)
    assets = [kali, printer]
    asset_map = {str(current.id): current for current in assets}
    graph = graph_for(
        assets,
        [
            (
                KALI_ID,
                PRINTER_ID,
                "connects_to",
                "same subnet",
                1.0,
                "T1018",
                "Remote System Discovery",
            ),
        ],
    )
    findings = [
        finding(PRINTER_ID, 9100, "CVE-2099-0001", "printer", cvss=9.8, epss=0.6, kev=True),
    ]

    monkeypatch.setattr(attack_engine, "_load_graph", lambda *_: (graph, assets, asset_map))

    result = attack_engine.simulate_from(
        database=FakeDatabase(findings),
        owner_id=OWNER_ID,
        source_id=str(KALI_ID),
    )

    assert result["attack_chains"] == []
    assert result["top_chain"] is None


def test_simulation_filters_kev_internet_and_critical_paths(monkeypatch):
    kali = asset(KALI_ID, "Kali", "192.168.56.10")
    linux = asset(LINUX_ID, "Linux Host", "192.168.56.20", criticality="medium", exposure="internal", risk_score=35)
    windows = asset(WINDOWS_ID, "Windows Host", "192.168.56.30", criticality="critical", exposure="external", risk_score=88)
    assets = [kali, linux, windows]
    asset_map = {str(current.id): current for current in assets}
    graph = graph_for(
        assets,
        [
            (KALI_ID, LINUX_ID, "exposes_remote", "remote access service on port 22", 5.5, "T1021.004", "Remote Services: SSH"),
            (KALI_ID, WINDOWS_ID, "shares_files", "file sharing service on port 445", 9.0, "T1021.002", "Remote Services: SMB/Admin Shares"),
        ],
    )
    findings = [
        finding(LINUX_ID, 22, None, "ssh", cvss=4.0, epss=0.05, kev=False, severity=FindingSeverity.LOW),
        finding(WINDOWS_ID, 445, "CVE-2017-0144", "smb", cvss=9.3, epss=0.73, kev=True, severity=FindingSeverity.CRITICAL),
    ]
    monkeypatch.setattr(attack_engine, "_load_graph", lambda *_: (graph, assets, asset_map))

    result = attack_engine.simulate_from(
        database=FakeDatabase(findings),
        owner_id=OWNER_ID,
        source_id=str(KALI_ID),
        kev_only=True,
        internet_exposed_only=True,
        critical_only=True,
    )

    assert len(result["attack_chains"]) == 1
    assert result["attack_chains"][0]["target_id"] == str(WINDOWS_ID)
    assert result["attack_chains"][0]["exploited_cves"][0]["cve_id"] == "CVE-2017-0144"
