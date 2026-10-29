"""Follow route-to-interface and declared-link edges in an AGE graph."""
import re
from uuid import UUID


def _uuid(value):
    return str(UUID(str(value)))


def _query(cur, graph, cypher):
    if not re.fullmatch(r"navis_[0-9a-f]{32}", graph):
        raise ValueError("invalid graph name")
    cur.execute(f"SELECT * FROM ag_catalog.cypher('{graph}', $$ {cypher} $$) AS (v ag_catalog.agtype)")
    return cur.fetchall()


def next_hops(cur, graph, route_id):
    """Find devices connected to the route's outgoing interface, either link direction."""
    import json
    route_id = _uuid(route_id)
    rows = []
    for link_type in ("MANUAL_LINK", "DISCOVERED_LINK"):
        rows.extend(_query(cur, graph, f"""MATCH (r:Route {{id: '{route_id}'}})-[:OUTGOING_INTERFACE]->(out:Interface),
            (out)-[:{link_type}]-(peer:Interface)<-[:HAS_INTERFACE]-(device:Device)
            RETURN device.id"""))
    return sorted({str(UUID(json.loads(str(row[0])))) for row in rows})


def peer_interfaces(cur, graph, route_id, device_id):
    """Return graph interface IDs for a route's peer on a specified device."""
    import json
    route_id, device_id = _uuid(route_id), _uuid(device_id)
    rows = []
    for link_type in ("MANUAL_LINK", "DISCOVERED_LINK"):
        rows.extend(_query(cur, graph, f"""MATCH (r:Route {{id: '{route_id}'}})-[:OUTGOING_INTERFACE]->(out:Interface),
            (out)-[:{link_type}]-(peer:Interface)<-[:HAS_INTERFACE]-(device:Device {{id: '{device_id}'}})
            RETURN peer.id"""))
    return sorted({str(UUID(json.loads(str(row[0])))) for row in rows})
