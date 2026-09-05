import logging
from typing import List, Dict, Any, Tuple, Optional
from app.modules.intelligence.geoip import GeoIPService

logger = logging.getLogger(__name__)

class SMTPHopAnalyzer:
    """Analyzes SMTP Received: header relay chains and constructs graph nodes for visual forensics."""

    @classmethod
    def analyze_chain(
        cls,
        raw_hops: List[Dict[str, Any]],
        parsed_email: Optional[Dict[str, Any]] = None
    ) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]], Dict[str, Any]]:
        """
        Enriches chronological SMTP hops with GeoIP, reverse DNS, suspicious indicators,
        and generates ReactFlow nodes and edges.
        """
        enriched_hops = []
        originating_ip_data = None
        
        for idx, hop in enumerate(raw_hops):
            ip = hop.get("ip", "")
            geo = GeoIPService.lookup_ip(ip)
            
            # If this is the earliest public IP in the chain, it's the Originating IP
            is_originating = False
            if not geo.get("is_private") and originating_ip_data is None and ip != "0.0.0.0" and ip != "Internal Delivery Hub":
                is_originating = True
                originating_ip_data = geo
            
            # Anomaly checks
            is_suspicious = False
            anomaly_reasons = []
            
            if geo.get("is_tor_or_vpn"):
                is_suspicious = True
                anomaly_reasons.append("Tor Exit Node or VPN Relay identified")
                
            if geo.get("risk_multiplier", 0) > 0.8:
                is_suspicious = True
                anomaly_reasons.append(f"High-Risk Bulletproof Hosting ASN: {geo.get('asn')}")
                
            from_relay = hop.get("from_relay", "")
            if ".top" in from_relay or ".xyz" in from_relay or ".cc" in from_relay or "mail-relay-direct" in from_relay:
                is_suspicious = True
                anomaly_reasons.append(f"Suspicious TLD/Relay Hostname: {from_relay}")

            # If this is originating hop, synchronize with email authentication status
            if (is_originating or idx == 0) and parsed_email:
                if parsed_email.get("spf_status") == "FAIL":
                    is_suspicious = True
                    anomaly_reasons.append("SPF Authentication Failed (Spoofing Risk)")
                if parsed_email.get("dmarc_status") == "FAIL":
                    is_suspicious = True
                    anomaly_reasons.append("DMARC Domain Alignment Failed")
                if parsed_email.get("reply_to_mismatch"):
                    is_suspicious = True
                    anomaly_reasons.append("Reply-To Domain Mismatch Detected")

            enriched_hop = {
                "hop_index": idx,
                "from_relay": hop.get("from_relay"),
                "by_relay": hop.get("by_relay"),
                "protocol": hop.get("protocol", "ESMTP"),
                "ip": ip,
                "is_originating": is_originating,
                "country": geo.get("country", "XX"),
                "country_name": geo.get("country_name", "Unknown"),
                "city": geo.get("city", "Unknown"),
                "asn": geo.get("asn", "Unknown"),
                "isp": geo.get("isp", "Unknown"),
                "is_tor_or_vpn": geo.get("is_tor_or_vpn", False),
                "is_suspicious": is_suspicious,
                "anomaly_reasons": anomaly_reasons,
                "delay_ms": (idx + 1) * 85 # Simulated realistic relay latency
            }
            enriched_hops.append(enriched_hop)

        # Fallback if all were private/empty
        if not originating_ip_data:
            originating_ip_data = GeoIPService.lookup_ip("0.0.0.0")

        # Build ReactFlow visual graph structures
        graph_data = cls._generate_reactflow_graph(enriched_hops)
        
        return enriched_hops, originating_ip_data, graph_data

    @staticmethod
    def _generate_reactflow_graph(enriched_hops: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Builds ReactFlow compatible nodes and animated edges."""
        nodes = []
        edges = []
        
        x_spacing = 260
        y_pos = 120
        
        for idx, hop in enumerate(enriched_hops):
            node_id = f"hop-{idx}"
            
            # Node Type classification
            if hop["is_originating"]:
                node_role = "ORIGIN"
            elif idx == len(enriched_hops) - 1:
                node_role = "GATEWAY_DEST"
            else:
                node_role = "INTERMEDIATE_RELAY"
                
            nodes.append({
                "id": node_id,
                "type": "smtpHopNode",
                "position": {"x": 50 + (idx * x_spacing), "y": y_pos + (30 if idx % 2 == 1 else 0)},
                "data": {
                    "hopIndex": idx + 1,
                    "totalHops": len(enriched_hops),
                    "nodeRole": node_role,
                    "fromRelay": hop["from_relay"],
                    "byRelay": hop["by_relay"],
                    "ip": hop["ip"],
                    "country": hop["country"],
                    "countryName": hop["country_name"],
                    "city": hop["city"],
                    "asn": hop["asn"],
                    "protocol": hop["protocol"],
                    "isSuspicious": hop["is_suspicious"],
                    "isTorOrVpn": hop["is_tor_or_vpn"],
                    "anomalies": hop["anomaly_reasons"],
                    "delayMs": hop["delay_ms"]
                }
            })
            
            if idx > 0:
                prev_id = f"hop-{idx-1}"
                is_danger_edge = hop["is_suspicious"] or enriched_hops[idx-1]["is_suspicious"]
                edges.append({
                    "id": f"edge-{prev_id}-{node_id}",
                    "source": prev_id,
                    "target": node_id,
                    "animated": True,
                    "style": {
                        "stroke": "#ef4444" if is_danger_edge else "#06b6d4",
                        "strokeWidth": 2,
                        "strokeDasharray": "5 5" if is_danger_edge else "none"
                    },
                    "label": f"+{hop['delay_ms']}ms"
                })
                
        return {"nodes": nodes, "edges": edges}
