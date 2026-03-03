"""Quick idasql query helper for the inner PE."""
import sys, requests

URL = "http://127.0.0.1:8103/query"

def q(sql):
    r = requests.post(URL, data=sql, timeout=30)
    r.raise_for_status()
    j = r.json()
    if not j.get("success", "error" not in j):
        print(f"ERROR: {j.get('error')}", file=sys.stderr)
        return j
    return j

if __name__ == "__main__":
    sql = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else sys.stdin.read()
    result = q(sql)
    if "rows" in result:
        for row in result["rows"]:
            print("\t".join(str(c) for c in row))
    elif "error" in result:
        print(f"ERROR: {result['error']}")
