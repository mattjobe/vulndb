import ipaddress, requests, subprocess, time, os, sys
import pandas as pd
from datetime import date
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, Integer, String, Text, UniqueConstraint, Date, create_engine
from urllib.parse import quote
from stig_parser import convert_xccdf
from redminelib import Redmine
from tenable import reports
from subnet_def import vlans, sde_specifics

global BASE_PATH
if getattr(sys, 'frozen', False):
    BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(sys.executable)))
else:
    BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..'))

Base = declarative_base()

class NessusItems(Base):
    __tablename__ = 'nessus_items'
    id = Column(Integer, primary_key=True, autoincrement=True)
    PluginID = Column(Integer, nullable=False)
    VlanID = Column(Text)
    HostIP = Column(Text, nullable=False)
    Port = Column(Text)
    PluginName = Column(Text)
    Synopsis = Column(Text)
    Description = Column(Text)
    Risk = Column(String(20))
    Solution = Column(Text)
    CVE = Column(Text)
    LastAdded = Column(Date)
    FirstFound = Column(Date)

class StigItems(Base):
    __tablename__ = 'stig_items'
    id = Column(Integer, primary_key=True, autoincrement=True)
    VulnID = Column(String(50), nullable=False)
    RuleID = Column(String(100), nullable=False)
    StigID_update = Column(String(255), nullable=False)
    StigID_text = Column(String(255), nullable=False)
    Severity = Column(String(20))
    Cat = Column(String(20))
    Classification = Column(String(50))
    GroupTitle = Column(String(255))
    RuleTitle = Column(Text)
    Description = Column(Text)
    VulnDiscussion = Column(Text)
    FalsePositives = Column(Text)
    FalseNegatives = Column(Text)
    Documentable = Column(Text)
    Mitigations = Column(Text)
    SeverityOverrideGuidance = Column(Text)
    PotentialImpacts = Column(Text)
    ThirdPartyTools = Column(Text)
    MitigationControl = Column(Text)
    Responsibility = Column(Text)
    IAControls = Column(Text)
    CheckText_name = Column(String(255))
    CheckText_href = Column(String(255))
    FixText = Column(Text)
    CCI = Column(Text)
    LastAdded = Column(Date)
    FirstFound = Column(Date)
    __table_args__ = (UniqueConstraint('VulnID', 'RuleID', 'StigID_update', 'StigID_text', name='unique_index'),)

def connect_nessus_api(root):
    datacenter_nessus_url = 'https://10.10.20.17:8834'
    datacenter_access_key = '43f362ac8e744ad9dbf12a3cc5bb0cc6e4d53ea8a6d9b4a121aa16dce99beee4'
    datacenter_secret_key = '36bb9b93755fe7961b1f2182f1cdd29b537e047d19dcc770026ea7a9ed02ea15'
    datacenter_scan_id = 391
    datacenter_filepath = os.path.join(BASE_PATH, 'data',f'{date.today()}_report_datacenter.csv')
    
    sde_nessus_url = 'https://10.100.1.118:8834'
    sde_access_key = '0ca034b39b21f42d4173ffd496e671b3b8a0c41f3285478252d6a515a9350696'
    sde_secret_key = 'de022279e6f94cf85fe47187f008288edd252f92022ad617ede517c83c82d95c'
    sde_scan_id = 2654
    sde_filepath = os.path.join(BASE_PATH, 'data',f'{date.today()}_report_SDE.csv')

    download_nessus_report(root, datacenter_nessus_url, datacenter_access_key, datacenter_secret_key, datacenter_scan_id, datacenter_filepath)
    root.init_processing([datacenter_filepath])
    download_nessus_report(root, sde_nessus_url, sde_access_key, sde_secret_key, sde_scan_id, sde_filepath)
    root.init_processing([sde_filepath])

def download_nessus_report(root, access_url, access_key, secret_key, scan_id, filepath):
    headers = {
        "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
        "Content-Type": "application/json",
    }
    export_url = f"{access_url}/scans/{scan_id}/export"
    payload = {"format": "csv"}
    try:
        export_response = requests.post(export_url, json=payload, headers=headers, verify=False)
    except Exception as e:
        root.write_error(f'Error: {e}\n')
        return
    
    if 'error' not in export_response.json():
        file_id = export_response.json()["file"]
        export_token = export_response.json()["token"]
        status_url = f"{access_url}/scans/{scan_id}/export/{file_id}/status"
        download_url = f"{access_url}/tokens/{export_token}/download"

        def check_status(response):
            return response.json().get('status') == 'ready'
        
        def download_report():
            response = requests.get(download_url, headers=headers, verify=False)
            open(filepath, 'wb').write(response.content)

        while True:
            response = requests.get(status_url, headers=headers, verify=False)
            if response.status_code == 200 and check_status(response):
                root.write_output('Ready. Downloading...\n')
                download_report()
                break
            elif response.status_code == 404:
                root.write_output('Error 404\n')
                break
            else:
                root.write_output('Waiting for report to be ready...\n')
                time.sleep(2) 
    else:
        root.write_error(export_response.json())

    return

def find_vlan_id(ip):
    for vlan_id, vlan_data in vlans.items():
        subnet_list = vlan_data[0]
        for subnet in subnet_list:
            if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(subnet, strict=False):
                return vlan_id
    return None

def aggregate_nessus_data(data):
    data = data.loc[:, data.columns.intersection([column.name for column in NessusItems.__table__.columns])]
    data = data.where(pd.notnull(data), None)

    def process_cve(cve):
        if type(cve) == list:
            return ', '.join(cve)
        else:
            return cve
    data['CVE'] = data.copy()['CVE'].apply(process_cve)

    data['VlanID'] = data['HostIP'].apply(find_vlan_id)

    def aggregate_columns(col):
        return lambda x: ', '.join(set(filter(None, x.astype(str))))
    
    aggregation_functions = {column: aggregate_columns(column) for column in data.columns if column not in ['PluginID']}
    data = data.groupby('PluginID', as_index=False).agg(aggregation_functions)
    return data

def prepare_nessus_file(root):
    with open(root.input_filepath, 'r', encoding='utf-8') as nessus_file:
        report_dict = reports.NessusReportv2(nessus_file)
        data = pd.DataFrame.from_dict(report_dict)
    nessus_column_mapping = {
        'pluginID': 'PluginID',
        'host-ip': 'HostIP',
        'port': 'Port',
        'plugin_name': 'PluginName',
        'synopsis': 'Synopsis',
        'description': 'Description',
        'risk_factor': 'Risk',
        'solution': 'Solution',
        'cve': 'CVE'
    }
    data = data[data['risk_factor'].isin(['Critical', 'High'])]
    data = data.rename(columns=nessus_column_mapping)
    return aggregate_nessus_data(data)

def prepare_csv_file(root):
    data = pd.read_csv(root.input_filepath, encoding='utf-8')
    csv_column_mapping = {
        'Plugin ID': 'PluginID',
        'Host': 'HostIP',
        'Port': 'Port',
        'Name': 'PluginName',
        'Synopsis': 'Synopsis',
        'Description': 'Description',
        'Risk': 'Risk',
        'Solution': 'Solution',
        'CVE': 'CVE'
    }
    data = data[data['Risk'].isin(['Critical', 'High'])]
    data = data.rename(columns=csv_column_mapping)
    return aggregate_nessus_data(data)

def process_stig_file(root):
    with open(root.input_filepath, "r") as f:
        xml_file = f.read()

    jre_path = os.path.join(BASE_PATH, "lib", "jre")
    os.environ["JAVA_HOME"] = jre_path
    
    validation_path = os.path.join(BASE_PATH, 'lib', 'xccdfval-1.2.0', 'xccdfval.bat')
    root.write_output('Validating STIG file...\n')
    cmd = f'"{validation_path}" -xccdfversion 1.2 -file "{root.input_filepath}"'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)

    if result.stderr:
        root.write_output(f"Output: {result.stdout}\n")
        root.write_error(f"Error: {result.stderr}\n")
        
    failed_validation = "Number of documents that failed validation: 0" not in result.stdout
    if failed_validation:
        root.write_output("Validation failed.\n")
        return None
    else:
        root.write_output("Validation successful.\n")

    xml_file = xml_file.replace("cdf:", "")
    xml_file = xml_file.replace("check-content-ref", "check-content")
    stig_json = convert_xccdf(xml_file)

    # Flatten the STIG data
    rules_json = stig_json['Rules']
    flattened_rules_json = []
    for rule in rules_json:
        flat_rule = rule.copy()
        stig_id = rule['StigID']
        flat_rule['StigID_update'] = stig_id['@update']
        flat_rule['StigID_text'] = stig_id['#text']
        del flat_rule['StigID']
        check_text = rule['CheckText']
        flat_rule['CheckText_name'] = check_text['@name']
        flat_rule['CheckText_href'] = check_text['@href']
        del flat_rule['CheckText']
        flattened_rules_json.append(flat_rule)
    data = pd.DataFrame(flattened_rules_json)
    
    columns_included = ['VulnID', 'RuleID', 'StigID_update', 'StigID_text', 'Severity', 'Cat', 'Classification', 
                    'GroupTitle', 'RuleTitle', 'Description', 'VulnDiscussion', 'FalsePositives', 'FalseNegatives', 
                    'Documentable', 'Mitigations', 'SeverityOverrideGuidance', 'PotentialImpacts', 'ThirdPartyTools',
                    'MitigationControl', 'Responsibility', 'IAControls', 'CheckText_name', 'CheckText_href', 'FixText', 'CCI']
    data = data[columns_included]
    data = data.loc[:, data.columns.intersection([column.name for column in StigItems.__table__.columns])]
    data = data.where(pd.notnull(data), None)      
    return data

def connect_mysql(root):
    connection_base = (
        f"mysql+pymysql://{root.load_config('mysql_username')}:{quote(root.load_config('mysql_password'))}"
        f"@{root.load_config('host_ip')}:{root.load_config('mysql_port')}/"
    )
    sde_str = connection_base + 'sde'
    dc_str = connection_base + 'datacenter'
    stig_str = connection_base + 'stig'

    try:
        engine_sde = create_engine(sde_str, echo=False)
        engine_dc = create_engine(dc_str, echo=False)
        engine_stig = create_engine(stig_str, echo=False)

        NessusItems.__table__.create(engine_sde, checkfirst=True)
        NessusItems.__table__.create(engine_dc, checkfirst=True)
        StigItems.__table__.create(engine_stig, checkfirst=True)

        Session_sde = sessionmaker(bind=engine_sde)
        Session_dc = sessionmaker(bind=engine_dc)
        Session_stig = sessionmaker(bind=engine_stig)

        sql_session_sde = Session_sde()
        sql_session_dc = Session_dc()
        sql_session_stig = Session_stig()

    except Exception as e:
        root.write_error(f"Error connecting to mysql database: {e}\n")
        return None, None, None

    return sql_session_sde, sql_session_dc, sql_session_stig

def find_in_redmine(issues, item):
    for issue in issues:
            plugin_id, plugin_name = issue.subject.split(' - ')
            plugin_id = int(plugin_id)
            if item.PluginID == plugin_id:
                if issue.status.id == 3 or issue.status.id == 5:
                    return None
                else:
                    return issue
    return None

def censor_ips(ip_list):
    censored_ips = []
    for ip in ip_list.split(','):
        octets = ip.split('.')
        censored_ip = f'x.x.{octets[2]}.{octets[3]}'
        censored_ips.append(censored_ip)
    return ', '.join(censored_ips)

def generate_note(item):
    host_ips = item.HostIP.split(', ')

    def find_sde_specific_name(ip_address):
        for list_name, ip_list in sde_specifics.items():
            if ip_address in ip_list:
                return list_name
        return None

    # Group host IPs by their VLAN IDs
    vlan_groups = {}
    for host_ip in host_ips:
        vlan_id = find_vlan_id(host_ip)

        if vlan_id is not None:
            if find_sde_specific_name(host_ip) is not None:
                vlan_name = find_sde_specific_name(host_ip)
            else:
                vlan_name = vlans[vlan_id][1]

            if vlan_id not in vlan_groups:
                vlan_groups[vlan_id] = {'name': '', 'ips': []}

            vlan_groups[vlan_id]['name'] = vlan_name
            vlan_groups[vlan_id]['ips'].append(host_ip)

    vlans_lines = []
    for vlan_id, data in vlan_groups.items():
        vlans_lines.append(f"{data['name']}:")
        vlans_lines.append(f"\t{', '.join(data['ips'])}")
    vlans_text = "\n".join(vlans_lines)

    note = f"*Hosts*\n<pre>{vlans_text}</pre>\n\n*Ports*\n{item.Port}"
    return note

def update_redmine(root, redmine, project_name, sql_session):
    root.write_output('\nFetching data from Redmine...\n')

    project = redmine.project.get(f"{project_name}")

    issues = redmine.issue.filter(project_id=project.id, status_id="*")
    custom_fields = redmine.custom_field.all(resource='issue')
    hostip_field_id = next((field.id for field in custom_fields if field.name == 'HostIP'), None)

    root.write_output(f"Project \'{project_name}\' found -- {len(issues)} issues.\n")

    # Delete all issues in the project
    if root.check_var.get():    
        root.write_output(f"Deleting all issues...\n")
        for issue in issues:
            redmine.issue.delete(issue.id)
        root.write_output(f"Deleted all issues.\n")
        issues = redmine.issue.filter(project_id=project.id, status_id="*")
    
    # Update the issues
    root.write_output(f"Updating issues...\n")
    try:
        nessus_items = sql_session.query(NessusItems).all()
        if len(nessus_items) == 0:
            return

        plugin_id_list = set(item.PluginID for item in nessus_items)
        if len(issues) != 0:
            for issue in issues:
                if issue is not None:
                    issue_plugin_id, plugin_name = issue.subject.split(' - ')
                    issue_plugin_id = int(issue_plugin_id) 
                    if issue_plugin_id not in plugin_id_list:
                        # dont need to do anything if the issue is already closed
                        if issue.status.id == 3 or issue.status.id == 5:
                            continue
                        closed_status_id = 5
                        redmine.issue.update(issue.id, status_id=closed_status_id)
                        issue.notes = f"Issue Closed: The plugin ID {issue_plugin_id} was not found in the latest scan results."
                        issue.save()

        for item in nessus_items:
            sorted_myql_hosts = ', '.join(sorted(item.HostIP.split(', '), key=ipaddress.IPv4Address))
            if len(issues) == 0:
                existing_issue = None
            else:
                existing_issue = find_in_redmine(issues, item)
            if existing_issue is not None:
                try:
                    def get_custom_field_value(issue, field_id):
                        for custom_field in issue.custom_fields:
                            if custom_field.id == field_id:
                                return custom_field.value
                        return None

                    existing_issue=redmine.issue.get(existing_issue.id)
                    issue_hosts = get_custom_field_value(existing_issue, hostip_field_id)
                except Exception as e:
                    root.write_error(f"Error getting issue #{existing_issue.id}: {e}\n")
                    continue

                if sorted_myql_hosts != issue_hosts:
                    existing_issue = redmine.issue.get(existing_issue.id)
                    existing_issue.notes = generate_note(item)

                    # Find the custom field and update its value
                    updated_custom_fields = []
                    for custom_field in existing_issue.custom_fields:
                        if custom_field.id == hostip_field_id:
                            custom_field.value = item.HostIP
                        updated_custom_fields.append({'id': custom_field.id, 'value': custom_field.value})

                    # Update the issue with the modified custom fields
                    redmine.issue.update(existing_issue.id, custom_fields=updated_custom_fields, notes=existing_issue.notes)

            else:
                priority = None
                if item.Risk == 'Critical':
                    priority = 4
                elif item.Risk == 'High':    
                    priority = 3

                def truncate_subject(subject, max_length=255):
                    if len(subject) > max_length:
                        return subject[:max_length - 3] + "..."
                    return subject

                # Create a new issue
                new_issue = redmine.issue.create(
                    project_id=project.id,
                    subject=truncate_subject(f"{item.PluginID} - {item.PluginName}"),
                    description=f"{item.Description}\n\n*Solution*\n\n{item.Solution}\n\n*References*\n\n{item.CVE}",
                    status_id=1,  # status = new
                    priority_id=priority,
                    custom_fields = [{'id': hostip_field_id, 'value': sorted_myql_hosts}]
                )
                new_issue.notes = generate_note(item)
                new_issue.save()
                #print(f"Issue #{new_issue.id} created successfully for {item.PluginID} - {item.HostIP}")
    except Exception as e:
        root.write_error(f"Error updating issues: {e}\n")
        return
    finally:
        sql_session.close()
    root.write_output(f"Done.\n\n")

def connect_redmine(root):
    sql_session_sde, sql_session_dc, sql_session_stig = connect_mysql(root)

    root.write_output('\nConnecting to Redmine...\n')
    api_key = root.load_config('redmine_key')
    try:
        redmine = Redmine(root.load_config('redmine_url'), key=api_key, requests={'verify': False})
    except Exception as e:
        root.write_error(f"Error connecting to Redmine: {e}\n")
        return
    root.write_output(f"Connected to Redmine.\n\n")

    update_redmine(root, redmine, 'sde-nessus', sql_session_sde)
    update_redmine(root, redmine, 'data-center-nessus', sql_session_dc)

    root.write_output("\n--FINISHED--\n")
    root.START_TIME = None

def update_stig_table(dataframe, session):
    for _, row in dataframe['data'].iterrows():
        record = session.query(StigItems).filter((StigItems.VulnID == row['VulnID'])).first()
        if record:
            record.LastAdded = row['LastAdded']
        else:
            record = StigItems(**row.to_dict())
            session.add(record)

def remove_unmatched_plugin_ids(root, plugin_id_list, sql_session):
    rows_deleted = sql_session.query(NessusItems).filter(NessusItems.PluginID.notin_(plugin_id_list)).delete(synchronize_session=False)
    sql_session.commit()
    #root.write_output(f"Removed {rows_deleted} plugin rows from the table based on new input.\n")

def update_nessus_table(root, dataframe, session):
    plugin_id_list = []
    for _, row in dataframe['data'].iterrows():
        plugin_id_list.append(row['PluginID'])
        record = session.query(NessusItems).filter((NessusItems.PluginID == row['PluginID'])).first()
        if record:
            record.HostIP = row['HostIP']
            record.LastAdded = row['LastAdded']
        else:
            record = NessusItems(**row.to_dict())
            session.add(record)
    remove_unmatched_plugin_ids(root, plugin_id_list, session)

def update_database(root, dataframe_list): 
    sql_session_sde, sql_session_dc, sql_session_stig = connect_mysql(root)

    for df in dataframe_list:
        df['data']['LastAdded'] = date.today()
        df['data']['FirstFound'] = date.today()

        if df['type'] == '.nessus' or df['type']== '.csv':
            if df['db'] == 'sde':
                update_nessus_table(root, df, sql_session_sde)
                sql_session_sde.commit()
            elif df['db'] == 'datacenter':
                update_nessus_table(root, df, sql_session_dc)
                sql_session_dc.commit()

        elif df['type'] == '.xml' and df['db'] == 'stig':
            update_stig_table(df, sql_session_stig)
            sql_session_stig.commit()
    sql_session_sde.close(), sql_session_dc.close(), sql_session_stig.close()