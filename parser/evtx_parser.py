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

                    system = root.find("{*}System")

                    if system is not None:
                        for child in system:
                            tag = child.tag.split("}")[-1].lower()

                            if tag == "timecreated":
                                row["utc_time"] = child.attrib.get("SystemTime")

                            elif tag == "eventid":
                                row["event_id"] = child.text

                            elif tag == "execution":
                                row["process_id"] = child.attrib.get("ProcessID")

                            elif tag == "providername":
                                row["provider"] = child.attrib.get("Name")

                            elif child.text:
                                row[tag] = child.text

                    event_data = root.find("{*}EventData")

                    if event_data is not None:
                        for d in event_data.findall("{*}Data"):
                            name = d.attrib.get("Name")
                            if name:
                                row[name.lower()] = d.text

                    rows.append(row)

                except Exception as e:
                    logging.debug(f"Skipped record: {e}")

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
        all_records.extend(parse_evtx_file(f))

    df = pd.DataFrame(all_records)

    # PADRONIZAÇÃO FINAL
    df.columns = [c.lower() for c in df.columns]

    if "processid" in df.columns and "process_id" not in df.columns:
        df["process_id"] = df["processid"]

    if "systemtime" in df.columns and "utc_time" not in df.columns:
        df["utc_time"] = df["systemtime"]

    if "eventid" in df.columns:
        df["event_id"] = pd.to_numeric(df["eventid"], errors="coerce")

    return df