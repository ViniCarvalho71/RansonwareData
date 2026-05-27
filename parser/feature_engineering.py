import pandas as pd
import numpy as np
import logging

def extract_behavioral_features(df: pd.DataFrame) -> pd.DataFrame:

    logging.info("Starting robust feature engineering")

    df = df.copy()
    df.columns = [c.lower() for c in df.columns]
    df.fillna("", inplace=True)

    # ----------------------------
    # PADRONIZAÇÃO
    # ----------------------------
    df["process_id"] = pd.to_numeric(df.get("process_id", 0), errors="coerce").fillna(0)
    df["event_id"] = pd.to_numeric(df.get("event_id", 0), errors="coerce").fillna(0)

    time_col = "utc_time"
    if time_col in df.columns:
        df[time_col] = pd.to_datetime(df[time_col], errors="coerce")

    group_col = "process_guid" if "process_guid" in df.columns else "process_id"

    features = []

    for key, g in df.groupby(group_col):

        if len(g) == 0:
            continue

        g = g.sort_values(time_col) if time_col in g.columns else g

        total = len(g)

        # tempo
        if time_col in g.columns and len(g) > 1:
            time_span = (g[time_col].max() - g[time_col].min()).total_seconds()
        else:
            time_span = 1.0

        time_span = max(time_span, 1.0)

        # ----------------------------
        # EVENTOS BASE
        # ----------------------------
        e1 = (g["event_id"] == 1).sum()
        e3 = (g["event_id"] == 3).sum()
        e11 = (g["event_id"] == 11).sum()

        registry = g["event_id"].isin([12, 13, 14]).sum()
        dns = (g["event_id"] == 22).sum()

        # ----------------------------
        # RATIOS (MELHORIA PRINCIPAL)
        # ----------------------------
        file_ratio = e11 / total
        registry_ratio = registry / total
        network_ratio = e3 / total
        dns_ratio = dns / total

        # densidade temporal
        events_per_sec = total / time_span

        # burst
        if time_col in g.columns:
            burst = g.groupby(g[time_col].dt.floor("s")).size().max()
        else:
            burst = 0

        burst_ratio = burst / total

        # arquivos suspeitos
        suspicious_ext = 0
        if "targetfilename" in g.columns:
            fns = g["targetfilename"].astype(str).str.lower()
            exts = fns.str.split(".").str[-1]

            suspicious_ext = exts.isin([
                "exe","dll","bat","ps1","vbs","scr","zip","rar","enc"
            ]).sum() / total

        # comandos suspeitos (NORMALIZADO)
        cmd_ratio = 0
        if "commandline" in g.columns:
            cmds = g["commandline"].astype(str).str.lower()
            cmd_ratio = cmds.str.contains(
                "powershell|wmic|vssadmin|bcdedit|cipher",
                regex=True
            ).sum() / total

        # imagem
        image = str(g["image"].iloc[0]).lower() if "image" in g.columns else ""

        label = g["label"].max() if "label" in g.columns else -1

        features.append({
            "process_key": key,

            # base
            "total_events": total,
            "events_per_sec": events_per_sec,

            # ratios (MELHOR GENERALIZAÇÃO)
            "file_ratio": file_ratio,
            "registry_ratio": registry_ratio,
            "network_ratio": network_ratio,
            "dns_ratio": dns_ratio,

            # comportamento temporal
            "burst_ratio": burst_ratio,

            # heurísticas normalizadas
            "suspicious_ext_ratio": suspicious_ext,
            "suspicious_cmd_ratio": cmd_ratio,

            # contexto
            "image": image,
            "label": label
        })

    return pd.DataFrame(features)