#!/usr/bin/env python3


def ip_address(session, vt_url, ip):
    result = {}
    resp = session.get(f"{vt_url}/ip_addresses/{ip}")
    if resp.ok:
        data = resp.json()["data"]["attributes"]

        analysis = data["last_analysis_stats"]
        country = data["country"]
        votes = data["last_analysis_results"]
        mal_votes = [vote for vote in votes if votes[vote]["result"] == "clean"]

        result["analysis"] = analysis
        result["country"] = country
        result["mal_votes"] = mal_votes
        
    return result
