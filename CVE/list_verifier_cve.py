#!/usr/bin/env python3
"""
list_verifier_cve.py - Lista CVE verifier senza exploit e non analizzate

Filtri applicati:
1. category contiene "verifier"
2. exploit è vuoto (nessun exploit esistente)
3. partiallyAnalyzed è vuoto (non già analizzata)

Output: execution/verifier_cve_list.txt

Uso: python list_verifier_cve.py
"""

import pandas as pd
from pathlib import Path

# Paths
CSV_FILE = Path(__file__).parent.parent / "eBPF_CVEs_new_exploits(Sheet1).csv"
OUTPUT_FILE = Path(__file__).parent / "verifier_cve_list.txt"

def main():
    # Carica CSV
    print(f"[*] Caricamento: {CSV_FILE}")
    df = pd.read_csv(CSV_FILE, encoding='latin-1')
    print(f"    Totale righe: {len(df)}")
    
    # FILTRO 1: category contiene "verifier"
    m1 = df['category'].astype(str).str.lower().str.contains('verifier', na=False)
    
    # FILTRO 2: exploit vuoto
    m2 = df['exploit'].isna() | (df['exploit'].astype(str).str.strip().isin(['', '/', '-', 'nan']))
    
    # FILTRO 3: partiallyAnalyzed vuoto  
    m3 = df['partiallyAnalyzed'].isna() | (df['partiallyAnalyzed'].astype(str).str.strip().str.upper().isin(['', 'NAN']))
    
    # Applica filtri
    candidates = df[m1 & m2 & m3].sort_values('cveId', ascending=False)
    
    print(f"\n[*] Dopo filtri:")
    print(f"    - Filtro 1 (verifier): {m1.sum()} righe")
    print(f"    - Filtro 2 (no exploit): {m2.sum()} righe")
    print(f"    - Filtro 3 (not analyzed): {m3.sum()} righe")
    print(f"    - TUTTI I FILTRI: {len(candidates)} righe")
    
    # Genera output
    lines = []
    lines.append("=" * 70)
    lines.append("CVE CANDIDATE - VERIFIER + NO EXPLOIT + NOT ANALYZED")
    lines.append("=" * 70)
    lines.append("")
    
    for i, (_, row) in enumerate(candidates.iterrows(), 1):
        cve = row['cveId']
        title = str(row.get('title', 'N/A'))[:50]
        cvss = str(row.get('maxSeverityScore', 'N/A'))
        cat = row['category']
        
        lines.append(f"{i:3}. {cve}")
        lines.append(f"     CVSS: {cvss}")
        lines.append(f"     Title: {title}")
        lines.append(f"     Category: {cat}")
        lines.append("")
    
    lines.append("=" * 70)
    lines.append(f"TOTALE: {len(candidates)} CVE")
    lines.append("=" * 70)
    
    # Salva
    output = "\n".join(lines)
    with open(OUTPUT_FILE, 'w') as f:
        f.write(output)
    
    print(f"\n[+] Salvato in: {OUTPUT_FILE}")
    print(f"\n{output}")

if __name__ == "__main__":
    main()
