import pandas as pd
import numpy as np
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def extract_behavioral_features(df: pd.DataFrame) -> pd.DataFrame:

    logging.info("Starting robust feature engineering")

    df = df.copy()

    # ---------------------------------
    # LOWERCASE + CLEAN
    # ---------------------------------
    df.columns = [
        str(c).lower().strip()
        for c in df.columns
    ]

    # ---------------------------------
    # COLUMN NORMALIZATION
    # ---------------------------------
    rename_map = {
        "processid": "process_id",
        "processguid": "process_guid",
        "eventid": "event_id",
        "utctime": "utc_time",
        "targetfilename": "targetfilename",
        "commandline": "commandline",
        "image": "image",
        "label": "label",
        "parentprocessguid": "parent_process_guid"
    }

    df.rename(columns=rename_map, inplace=True)

    # ---------------------------------
    # REMOVE DUPLICATED COLUMNS
    # IMPORTANT: MUST BE AFTER RENAME
    # ---------------------------------
    df = df.loc[:, ~df.columns.duplicated()].copy()

    # ---------------------------------
    # REQUIRED COLUMNS
    # ---------------------------------
    required = ["process_id", "event_id"]

    for col in required:

        if col not in df.columns:
            raise ValueError(
                f"Missing required column: {col}"
            )

    # ---------------------------------
    # FILLNA
    # ---------------------------------
    df.fillna("", inplace=True)

    # ---------------------------------
    # ENSURE SERIES (FIX FOR DUPLICATES)
    # ---------------------------------
    if isinstance(df["process_id"], pd.DataFrame):
        df["process_id"] = df["process_id"].iloc[:, 0]

    if isinstance(df["event_id"], pd.DataFrame):
        df["event_id"] = df["event_id"].iloc[:, 0]

    # ---------------------------------
    # TYPE CONVERSION
    # ---------------------------------
    df["process_id"] = pd.to_numeric(
        df["process_id"],
        errors="coerce"
    ).fillna(0)

    df["event_id"] = pd.to_numeric(
        df["event_id"],
        errors="coerce"
    ).fillna(0)

    # ---------------------------------
    # DATETIME
    # ---------------------------------
    time_col = "utc_time"

    if time_col in df.columns:

        df[time_col] = pd.to_datetime(
            df[time_col],
            errors="coerce"
        )

    # ---------------------------------
    # GROUPING
    # ---------------------------------
    group_col = (
        "process_guid"
        if "process_guid" in df.columns
        else "process_id"
    )

    print("Grouping by:", group_col)

    features = []

    # ---------------------------------
    # FEATURE EXTRACTION
    # ---------------------------------
    for key, g in df.groupby(group_col):

        if len(g) == 0:
            continue

        # ---------------------------------
        # SORT BY TIME
        # ---------------------------------
        if time_col in g.columns:
            g = g.sort_values(time_col)

        total = len(g)

        # ---------------------------------
        # TIME SPAN
        # ---------------------------------
        if time_col in g.columns:

            valid_times = g[time_col].dropna()

            if len(valid_times) > 1:

                time_span = (
                    valid_times.max() -
                    valid_times.min()
                ).total_seconds()

            else:
                time_span = 1.0

        else:
            time_span = 1.0

        time_span = max(time_span, 1.0)

        # ---------------------------------
        # EVENT COUNTS
        # ---------------------------------
        e1 = (g["event_id"] == 1).sum()
        e3 = (g["event_id"] == 3).sum()
        e11 = (g["event_id"] == 11).sum()

        registry = g["event_id"].isin(
            [12, 13, 14]
        ).sum()

        dns = (g["event_id"] == 22).sum()

        # ---------------------------------
        # RATIOS
        # ---------------------------------
        file_ratio = e11 / total
        registry_ratio = registry / total
        network_ratio = e3 / total
        dns_ratio = dns / total

        file_creation_rate = e11 / time_span

        # ---------------------------------
        # TEMPORAL FEATURES
        # ---------------------------------
        events_per_sec = total / time_span

        burst = 0

        if time_col in g.columns:

            g_valid = g.dropna(
                subset=[time_col]
            )

            if len(g_valid) > 0:

                burst = (
                    g_valid.groupby(
                        g_valid[time_col]
                        .dt.floor("s")
                    )
                    .size()
                    .max()
                )

                if pd.isna(burst):
                    burst = 0

        burst_ratio = (
            burst / total
            if total > 0 else 0
        )

        # ---------------------------------
        # SUSPICIOUS EXTENSIONS
        # ---------------------------------
        suspicious_ext_ratio = 0
        unique_extensions_modified = 0

        if "targetfilename" in g.columns:

            fns = (
                g["targetfilename"]
                .astype(str)
                .str.lower()
            )

            exts = (
                fns.str.split(".")
                .str[-1]
            )

            suspicious_ext_ratio = exts.isin([
                "exe",
                "dll",
                "bat",
                "ps1",
                "vbs",
                "scr",
                "zip",
                "rar",
                "enc",
                "encrypted",
                "locky"
            ]).sum() / total

            unique_extensions_modified = (
                exts.nunique()
            )

        # ---------------------------------
        # SUSPICIOUS COMMANDS
        # ---------------------------------
        suspicious_cmd_ratio = 0

        if "commandline" in g.columns:

            cmds = (
                g["commandline"]
                .astype(str)
                .str.lower()
            )

            suspicious_cmd_ratio = cmds.str.contains(
                r"powershell|wmic|vssadmin|bcdedit|cipher",
                regex=True,
                na=False
            ).sum() / total

        # ---------------------------------
        # CHILD PROCESS COUNT
        # ---------------------------------
        child_process_count = 0

        if "parent_process_guid" in g.columns:

            child_process_count = (
                g["parent_process_guid"]
                .astype(str)
                .nunique()
            )

        # ---------------------------------
        # LABEL
        # ---------------------------------
        label = -1

        if "label" in g.columns:

            label = pd.to_numeric(
                g["label"],
                errors="coerce"
            ).fillna(0).max()

        # ---------------------------------
        # FINAL FEATURES
        # ---------------------------------
        features.append({

            "process_key": key,

            # base
            "total_events": total,
            "events_per_sec": events_per_sec,

            # ratios
            "file_ratio": file_ratio,
            "registry_ratio": registry_ratio,
            "network_ratio": network_ratio,
            "dns_ratio": dns_ratio,

            # temporal
            "burst_ratio": burst_ratio,
            "file_creation_rate": file_creation_rate,

            # suspicious behavior
            "suspicious_ext_ratio":
                suspicious_ext_ratio,

            "suspicious_cmd_ratio":
                suspicious_cmd_ratio,

            # filesystem diversity
            "unique_extensions_modified":
                unique_extensions_modified,

            # process tree
            "child_process_count":
                child_process_count,

            # label
            "label": label
        })

    feat_df = pd.DataFrame(features)

    logging.info(
        f"Extracted features for "
        f"{len(feat_df)} processes"
    )

    return feat_df