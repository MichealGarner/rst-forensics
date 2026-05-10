"""Capture adapters — convert live/file packet sources into RstObservations.

Each adapter lazy-imports scapy inside its entry point so the package itself
remains importable (and the classifier remains testable) without scapy
installed. Use:

    from rst_forensics.adapters import pcap, passive, active

Then ``pcap.read(path)``, ``passive.sniff(...)``, ``active.probe(...)``.
"""
