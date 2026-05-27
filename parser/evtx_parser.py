import xml.etree.ElementTree as ET
from pathlib import Path
from Evtx.Evtx import Evtx
import pandas as pd
import logging

logging.basicConfig(level=logging.INFO)

def parse_evtx_file(path: Path) -> list:

    rows = []

    try:

        with Evtx(str(path)) as log:

            for record in log.records():

                try:

                    root = ET.fromstring(record.xml())

                    row = {
                        "_log_file": path.name
                    }

                    # ---------------------------------
                    # SYSTEM
                    # ---------------------------------
                    system = root.find("{*}System")

                    if system is not None:

                        for child in system:

                            tag = child.tag.split("}")[-1].lower()

                            # timestamp
                            if tag == "timecreated":

                                row["utc_time"] = (
                                    child.attrib.get("SystemTime")
                                )

                            # event id
                            elif tag == "eventid":

                                row["event_id"] = child.text

                            # execution/process info
                            elif tag == "execution":

                                row["process_id"] = (
                                    child.attrib.get("ProcessID")
                                )

                                row["thread_id"] = (
                                    child.attrib.get("ThreadID")
                                )

                            # provider
                            elif tag == "provider":

                                row["provider"] = (
                                    child.attrib.get("Name")
                                )

                            elif child.text:

                                row[tag] = child.text

                    # ---------------------------------
                    # EVENT DATA
                    # ---------------------------------
                    event_data = root.find("{*}EventData")

                    if event_data is not None:

                        for d in event_data.findall("{*}Data"):

                            name = d.attrib.get("Name")

                            if name:

                                row[name.lower()] = d.text

                    rows.append(row)

                except Exception as e:

                    logging.debug(
                        f"Skipped record in {path.name}: {e}"
                    )

    except Exception as e:

        logging.error(f"Error reading {path}: {e}")

    return rows


def parse_all_evtx(logs_dir: Path) -> pd.DataFrame:

    all_records = []

    logs_dir = Path(logs_dir)

    files = list(logs_dir.glob("*.evtx"))

    logging.info(f"{len(files)} EVTX files found")

    for f in files:

        logging.info(f"Parsing {f.name}")

        all_records.extend(
            parse_evtx_file(f)
        )

    df = pd.DataFrame(all_records)

    # ---------------------------------
    # LOWERCASE
    # ---------------------------------
    df.columns = [c.lower() for c in df.columns]

    # remove duplicated columns
    df = df.loc[:, ~df.columns.duplicated()]

    # ---------------------------------
    # NORMALIZATION
    # ---------------------------------
    rename_map = {
        "processguid": "process_guid",
        "processid": "process_id",
        "eventid": "event_id",
        "utctime": "utc_time",
        "parentprocessguid": "parent_process_guid",
    }

    df.rename(columns=rename_map, inplace=True)

    # remove duplicated columns AFTER rename
    df = df.loc[:, ~df.columns.duplicated()].copy()

    # ---------------------------------
    # TYPES
    # ---------------------------------
    if "event_id" in df.columns:

        df["event_id"] = pd.to_numeric(
            df["event_id"].squeeze(),
            errors="coerce"
        )

    if "process_id" in df.columns:

        df["process_id"] = pd.to_numeric(
            df["process_id"].squeeze(),
            errors="coerce"
        )

    return df