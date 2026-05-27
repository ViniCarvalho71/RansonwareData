import pandas as pd
import numpy as np
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def extract_behavioral_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Transforms raw Windows/Sysmon telemetry events into behavioral features
    grouped by ProcessGuid (preferred) or ProcessId.
    """

    logging.info("Starting feature engineering")

    df = df.copy()
    df.fillna('', inplace=True)

    # Normalize ProcessId
    if 'ProcessID' in df.columns and 'ProcessId' not in df.columns:
        df['ProcessId'] = df['ProcessID']

    elif 'Execution_ProcessID' in df.columns and 'ProcessId' not in df.columns:
        df['ProcessId'] = df['Execution_ProcessID']

    df['ProcessId'] = pd.to_numeric(
        df.get('ProcessId', 0),
        errors='coerce'
    ).fillna(0)

    # Normalize timestamp
    time_col = 'UtcTime'

    if 'SystemTime' in df.columns and 'UtcTime' not in df.columns:
        time_col = 'SystemTime'

    if time_col in df.columns:
        df[time_col] = pd.to_datetime(
            df[time_col],
            errors='coerce'
        )

    # Normalize EventID
    if 'EventID' not in df.columns:
        df['EventID'] = 0

    df['EventID'] = pd.to_numeric(
        df['EventID'],
        errors='coerce'
    ).fillna(0)

    # Better grouping
    group_col = 'ProcessGuid' if 'ProcessGuid' in df.columns else 'ProcessId'

    groups = df.groupby(group_col)

    features = []

    for process_key, group in groups:

        if len(group) == 0:
            continue

        group = group.sort_values(time_col) if time_col in group.columns else group

        # Time span
        if time_col in group.columns and len(group) > 1:

            time_span = (
                group[time_col].max() -
                group[time_col].min()
            ).total_seconds()

        else:
            time_span = 1.0

        if time_span <= 0:
            time_span = 1.0

        # Basic behavioral metrics
        total_events = len(group)

        events_per_second = total_events / time_span

        # Sysmon behavioral abstraction
        num_created_processes = (group['EventID'] == 1).sum()

        num_network_connections = (group['EventID'] == 3).sum()

        num_created_files = (group['EventID'] == 11).sum()

        num_registry_modifications = group['EventID'].isin(
            [12, 13, 14]
        ).sum()

        num_dns_queries = (group['EventID'] == 22).sum()

        # Burst activity
        if time_col in group.columns:

            per_second = group.groupby(
                group[time_col].dt.floor('s')
            ).size()

            max_events_same_second = per_second.max()

        else:
            max_events_same_second = 0

        # Network features
        num_unique_ips = (
            group['DestinationIp'].nunique()
            if 'DestinationIp' in group.columns
            else 0
        )

        num_unique_ports = (
            group['DestinationPort'].nunique()
            if 'DestinationPort' in group.columns
            else 0
        )

        # File behavior
        suspicious_extensions = 0
        unique_extensions_modified = 0
        critical_directory_activity = 0

        if 'TargetFilename' in group.columns:

            filenames = group['TargetFilename'].astype(str).str.lower()

            exts = filenames.apply(
                lambda x: x.split('.')[-1]
                if '.' in x else ''
            )

            suspicious_extensions = exts.isin([
                'exe',
                'dll',
                'bat',
                'vbs',
                'ps1',
                'scr',
                'cry',
                'encrypted',
                'locky',
                'cerber'
            ]).sum()

            unique_extensions_modified = exts.nunique()

            critical_paths = [
                'users',
                'documents',
                'desktop',
                'downloads',
                'appdata',
                'temp'
            ]

            critical_directory_activity = filenames.str.contains(
                '|'.join(critical_paths),
                case=False,
                regex=True
            ).sum()

        # File creation speed
        file_creation_rate = num_created_files / time_span

        # Child process indicators
        child_process_count = 0

        if 'ParentImage' in group.columns:
            child_process_count = group['ParentImage'].nunique()

        # Suspicious command execution
        suspicious_command_count = 0

        command_columns = []

        if 'CommandLine' in group.columns:
            command_columns.append('CommandLine')

        if 'ParentCommandLine' in group.columns:
            command_columns.append('ParentCommandLine')

        suspicious_commands = [
            'vssadmin',
            'wbadmin',
            'bcdedit',
            'cipher',
            'powershell',
            'wmic'
        ]

        for col in command_columns:

            suspicious_command_count += group[col].astype(str).str.lower().str.contains(
                '|'.join(suspicious_commands),
                regex=True
            ).sum()

        # Process image
        image_name = ''

        if 'Image' in group.columns:
            image_name = str(group['Image'].iloc[0]).lower()

        # Label
        label = -1

        if 'Label' in group.columns:
            label = group['Label'].max()

        log_file = ''

        if '_log_file' in group.columns:
            log_file = str(group['_log_file'].iloc[0])

        features.append({
             '_log_file': log_file,

            'ProcessKey': process_key,

            'Image': image_name,

            'total_events': total_events,

            'events_per_second': events_per_second,

            'max_events_same_second': max_events_same_second,

            'num_created_processes': num_created_processes,

            'num_created_files': num_created_files,

            'file_creation_rate': file_creation_rate,

            'num_registry_modifications': num_registry_modifications,

            'num_network_connections': num_network_connections,

            'num_dns_queries': num_dns_queries,

            'num_unique_ips': num_unique_ips,

            'num_unique_ports': num_unique_ports,

            'suspicious_extensions': suspicious_extensions,

            'unique_extensions_modified': unique_extensions_modified,

            'critical_directory_activity': critical_directory_activity,

            'child_process_count': child_process_count,

            'suspicious_command_count': suspicious_command_count,

            'Label': label
        })

    feat_df = pd.DataFrame(features)

    logging.info(
        f"Extracted features for {len(feat_df)} unique processes"
    )

    return feat_df