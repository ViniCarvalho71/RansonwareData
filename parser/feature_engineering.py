import pandas as pd
import numpy as np
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def extract_behavioral_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Transforms raw Windows/Sysmon telemetry events into abstract behavioral features
    grouped by ProcessId (representing the behavior of that process).
    """
    logging.info("Starting feature engineering (extracting behavioral features)")
    
    # Normalize ProcessId (if ProcessID exists instead of ProcessId)
    if 'ProcessID' in df.columns and 'ProcessId' not in df.columns:
        df['ProcessId'] = df['ProcessID']
    elif 'Execution_ProcessID' in df.columns and 'ProcessId' not in df.columns:
        df['ProcessId'] = df['Execution_ProcessID']
        
    df['ProcessId'] = pd.to_numeric(df['ProcessId'], errors='coerce')
    
    # Ensure UtcTime exists and is datetime
    time_col = 'UtcTime'
    if 'SystemTime' in df.columns and 'UtcTime' not in df.columns:
        time_col = 'SystemTime'
        
    if time_col in df.columns:
        df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
    
    # Optional: Fill missing EventIDs
    if 'EventID' not in df.columns:
        df['EventID'] = 0
    df['EventID'] = pd.to_numeric(df['EventID'], errors='coerce').fillna(0)

    # We will build features for each ProcessId
    groups = df.groupby('ProcessId')
    
    features = []
    
    for pid, group in groups:
        if pd.isna(pid) or pid == 0:
            continue
            
        group = group.sort_values(time_col) if time_col in group.columns else group
        
        # Calculate time span
        if time_col in group.columns and len(group) > 1:
            time_span = (group[time_col].max() - group[time_col].min()).total_seconds()
        else:
            time_span = 1.0  # minimal time span to avoid division by zero
            
        if time_span <= 0:
            time_span = 1.0
            
        # Basic counts
        total_events = len(group)
        events_per_second = total_events / time_span
        
        # Event type counts based on Sysmon Event IDs (used to compute behavioral features, NOT as final model features ideally, but they reflect the behavior)
        # Event 1: Process creation
        num_created_processes = (group['EventID'] == 1).sum()
        
        # Event 11: File creation
        num_created_files = (group['EventID'] == 11).sum()
        
        # Event 12, 13, 14: Registry modifications
        num_registry_modifications = group['EventID'].isin([12, 13, 14]).sum()
        
        # Event 3: Network connections
        num_network_connections = (group['EventID'] == 3).sum()
        
        # Event 22: DNS Activity
        num_dns_queries = (group['EventID'] == 22).sum()
        
        # Network features
        num_unique_ips = group['DestinationIp'].nunique() if 'DestinationIp' in group.columns else 0
        num_unique_ports = group['DestinationPort'].nunique() if 'DestinationPort' in group.columns else 0
        
        # Filesystem
        suspicious_extensions = 0
        if 'TargetFilename' in group.columns:
            exts = group['TargetFilename'].astype(str).str.lower().apply(lambda x: x.split('.')[-1] if '.' in x else '')
            suspicious_extensions = exts.isin(['exe', 'dll', 'bat', 'vbs', 'ps1', 'scr', 'cry', 'encrypted', 'locky', 'cerber']).sum()
            
        # Label (if available)
        label = -1
        if 'Label' in group.columns:
            # We assign the max label (1 if Ransomware, 0 if Benign)
            label = group['Label'].max()
            
        features.append({
            'ProcessId': pid,
            'total_events': total_events,
            'events_per_second': events_per_second,
            'num_created_processes': num_created_processes,
            'num_created_files': num_created_files,
            'num_registry_modifications': num_registry_modifications,
            'num_network_connections': num_network_connections,
            'num_dns_queries': num_dns_queries,
            'num_unique_ips': num_unique_ips,
            'num_unique_ports': num_unique_ports,
            'suspicious_extensions': suspicious_extensions,
            'Label': label
        })
        
    feat_df = pd.DataFrame(features)
    logging.info(f"Extracted features for {len(feat_df)} unique processes")
    return feat_df
