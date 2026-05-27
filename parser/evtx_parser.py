import xml.etree.ElementTree as ET
from pathlib import Path
from Evtx.Evtx import Evtx
import pandas as pd
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_evtx_file(path: Path) -> list:
    """
    Parse a single EVTX file to extract structured fields.
    """
    rows = []
    try:
        with Evtx(str(path)) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)
                    row = {"_log_file": path.name}

                    system = root.find("{*}System")
                    if system is not None:
                        for child in system:
                            tag = child.tag.split("}")[-1]
                            if tag == "TimeCreated":
                                row["SystemTime"] = child.attrib.get("SystemTime")
                            elif tag == "Provider":
                                if "Name" in child.attrib:
                                    row["Name"] = child.attrib.get("Name")
                            elif tag == "Execution":
                                if "ProcessID" in child.attrib:
                                    row["ProcessID"] = child.attrib.get("ProcessID")
                                if "ThreadID" in child.attrib:
                                    row["ThreadID"] = child.attrib.get("ThreadID")
                            elif tag == "Security":
                                if "UserID" in child.attrib:
                                    row["UserID"] = child.attrib.get("UserID")
                            elif tag == "EventID":
                                row[tag] = child.text
                            else:
                                if child.text is not None:
                                    row[tag] = child.text

                    event_data = root.find("{*}EventData")
                    if event_data is not None:
                        for d in event_data.findall("{*}Data"):
                            name = d.attrib.get("Name")
                            if name:
                                row[name] = d.text

                    user_data = root.find("{*}UserData")
                    if user_data is not None:
                        for elem in user_data.iter():
                            if elem is user_data:
                                continue
                            tag = elem.tag.split("}")[-1]
                            if elem.text is not None and tag not in row:
                                row[tag] = elem.text

                    rows.append(row)
                except Exception as e:
                    continue
    except Exception as e:
        logging.error(f"Error reading EVTX file {path}: {e}")
        
    return rows

def parse_all_evtx(logs_dir: Path) -> pd.DataFrame:
    all_records = []
    logs_dir = Path(logs_dir)
    evtx_files = list(logs_dir.glob("*.evtx"))
    
    logging.info(f"Found {len(evtx_files)} EVTX files in {logs_dir}")
    
    for p in sorted(evtx_files):
        logging.info(f"Parsing {p.name}...")
        records = parse_evtx_file(p)
        all_records.extend(records)
        
    df = pd.DataFrame(all_records)
    
    if "ProcessID" in df.columns and "ProcessId" not in df.columns:
        df["ProcessId"] = df["ProcessID"]
    if "SystemTime" in df.columns and "UtcTime" not in df.columns:
        df["UtcTime"] = df["SystemTime"]
        
    logging.info(f"Parsed {len(df)} total events.")
    return df
