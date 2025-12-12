from datetime import datetime, timezone

# Funções de cálculo da heurística (mesmo código que já tens)
def impacto(vuln):
    cve_data = vuln.get("CVE", [{}])[0]
    cvss = cve_data.get("CVSS", {}).get("score", 0)
    print(f"CVSS base score encontrado: {cvss}")
    return cvss

def prob_exploit(vuln):
    score = 0
    cve_data = vuln.get("CVE", [{}])[0]

    if cve_data.get("exploit_available"):
        print("Exploit disponível: +7 pontos")
        score += 7

    if "publishedDate" in cve_data:
        pub_date = datetime.fromisoformat(cve_data["publishedDate"].replace("Z", "+00:00"))
        age_years = (datetime.now(timezone.utc) - pub_date).days / 365
        age_years = max(0, age_years)
        print(f"Publicado há {age_years:.1f} anos")
        if age_years < 1:
            score += 3
        elif age_years < 5:
            score += 2
        else:
            score += 1

    return score

def exposicao_rede(vuln):
    score = 0

    # Host status
    if vuln.get("host_status") == "up":
        print("Host está UP → +3 pontos")
        score += 3
    else:
        print("Host está DOWN → +0 pontos")

    # Portas abertas
    open_ports = vuln.get("open_ports_count", 0)
    print(f"Portas abertas: {open_ports} → +{open_ports} pontos")
    score += open_ports

    # Categoria do dispositivo
    device_cat = vuln.get("device_category", "unknown")
    if device_cat == "unknown":
        print("Categoria do dispositivo desconhecida → +1 ponto")
        score += 1
    else:
        print(f"Categoria do dispositivo '{device_cat}' → +2 pontos")
        score += 2

    return score
def heuristica(vuln):
    print("\n==============================")
    cve_id = vuln.get("CVE", [{}])[0].get("cve_id", "CVE desconhecida")
    print(f"CALCULANDO HEURÍSTICA PARA {cve_id}")
    print("==============================")

    print("\n=== IMPACTO ===")
    imp = impacto(vuln)

    print("\n=== PROBABILIDADE DE EXPLORAÇÃO ===")
    prob = prob_exploit(vuln)

    print("\n=== EXPOSIÇÃO NA REDE ===")
    exp = exposicao_rede(vuln)

    total = imp + prob + exp

    print("\n=== TOTAL ===")
    print(f"Impacto: {imp}")
    print(f"Probabilidade de exploração: {prob}")
    print(f"Exposição na rede: {exp}")
    print(f"→ h(vulnerabilidade) = {total}\n")

    return total


# Função para processar múltiplas vulnerabilidades
def processar_vulnerabilidades(lista_vulns):
    resultados = []
    for vuln in lista_vulns:
        h = heuristica(vuln)
        resultados.append({
            "vulnerability": vuln,
            "h_score": h
        })

    # Ordenar do mais crítico para o menos crítico
    resultados.sort(key=lambda x: x["h_score"], reverse=True)

    print("\n=== VULNERABILIDADES ORDENADAS POR PRIORIDADE ===")
    for idx, res in enumerate(resultados):
        cve_id = res["vulnerability"]["CVE"][0].get("cve_id", "CVE desconhecida")
        print(f"{idx+1}. {cve_id} → h = {res['h_score']}")
        if idx == 0:
            print(">>> PRIORIDADE MÁXIMA: Tal como A* escolhe o melhor nó, esta vulnerabilidade deve ser tratada primeiro.\n")
    return resultados

# ==========================
# Exemplo de uso
vulnerabilidades = [
    {
        "CVE": [
            {
                "CVSS": {"score": 5, "vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P"},
                "cve_id": "CVE-2009-4811",
                "exploit_available": True,
                "publishedDate": "2025-12-11T00:00:00Z"
            }
        ],
        "host_status": "up",
        "open_ports_count": 6,
        "device_category": "unknown"
    },
    {
        "CVE": [
            {
                "CVSS": {"score": 7, "vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
                "cve_id": "CVE-2010-1234",
                "exploit_available": False,
                "publishedDate": "2024-06-01T00:00:00Z"
            }
        ],
        "host_status": "up",
        "open_ports_count": 2,
        "device_category": "server"
    }
]

# Rodar o processamento
processar_vulnerabilidades(vulnerabilidades)
