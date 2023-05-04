vlans = {
    '11': (["10.10.11.0/24"], "IAAS"),
    '76': (["10.10.76.0/24"], "Management & ILOM (MILOM)"),
    '77': (["10.10.77.0/24"], "Data Center APC Management"),
    '1000': (["10.10.14.0/24"], "SIF Uplink (aka Border Router)"),
    '1100': (["10.10.21.0/24"], "Int-Proj-Trans"),
    '2000': (["10.10.10.0/24"], "Exterior-Interior-Transit"),
    '2001': (["172.20.1.0/24"], "DMZ-Enterprise"),
    '2002': (["172.20.76.0/24"], "DMZ-Management"),
    '2003': (["172.20.4.0/24"], "DMZ-Project"),
    '2004': (["10.10.15.0/24"], "Exterior-Project-Transit"),
    '2010': (["10.10.40.0/24"], "Security"),
    '2100': (["10.10.20.0/24"], "DES"),
    '2106': (["10.10.30.0/24"], "PES"),
    '3000': (["192.168.1.0/24"], "Corporate Servers"),
    '3001': (["10.10.2.0/24"], "Corporate Workstations/Printers"),
    '900': (["10.10.90.0/24"], "DMZ (iSCSI)"),
    '901': (["10.10.91.0/24"], "SIF (iSCSI)"),
    '903': (["10.10.93.0/24"], "Corporate (iSCSI)"),
    '904': (["10.10.94.0/24"], "DES (iSCSI)"),
    '905': (["10.10.95.0/24"], "Project"),
    '906': (["10.10.96.0/24"], "PES (iSCSI)"),
    '600': (["192.168.76.0/24"], "DS Corp Wifi Mgmt"),
    '601': (["192.168.12.0/24"], "DS Guest Wifi Network"),
    '602': (["192.168.13.0/24"], "DS Corporate Wifi Network"),
    '603': (["192.168.100.0/24"], "PS Wifi Network"),
    '604': (["192.168.51.0/24"], "DS880 Wifi Network"),
    '3009': (["192.168.9.0/24"], "Lab Network"),
    '3010': (["192.168.10.0/24"], "T-7 Test Net"),
    '2105': (["10.10.5.0/24"], "POC DES"),
    '2005': (["172.20.5.0/24"], "POC-DMZ"),
    '1500': (["10.10.150.0/24"], "SDE Uplink"),
    '100': (["10.100.0.0/23", "10.100.1.0/23"], "SDE-Mgt-ILOM"),
    '101': (["10.100.3.0/24"], "Mgt_MAP"),
    '200': (["10.101.100.0/24"], "SDE-DEV-Mgt-VMs"),
    '210': (["10.101.10.0/24"], "R12 DEV_DB"),
    '220': (["10.101.20.0/24"], "R12 DEV_App"),
    '230': (["10.101.30.0/24"], "R12 DEV_DMZ"),
    '300': (["10.102.100.0/24"], "SDE-CM-Mgt-VMs"),
    '310': (["10.102.10.0/24"], "R12 CM_DB"),
    '320': (["10.102.20.0/24"], "R12 CM_APP"),
    '330': (["10.102.30.0/24"], "R12 CM_DMZ"),
    '400': (["10.103.100.0/24"], "SDE-CM-INT-VMs"),
    '410': (["10.103.10.0/24"], "R12 INT_DB"),
    '420': (["10.103.20.0/24"], "R12 INT_App"),
    '430': (["10.103.30.0/24"], "R12 INT_DMZ"),
    '1201': (["10.10.100.0/24"], "KVM Test Mgmt (formerly USPS RIMS Mgmt)"),
    '1203': (["10.10.103.0/24"], "TED network"),
    '500': (["10.50.0.0/24"], "DR MILOM"),
    '501': (["10.50.1.0/24"], "DR Production"),
    '502': (["10.50.2.0/24"], "DR Storage"),
    '503': (["10.50.3.0/24"], "DR DMZ"),
    '504': (["10.50.4.0/24"], "DR DES"),
    '505': (["10.50.5.0/24"], "DR Project Transit")
}

sde_specifics = {
    'SDE-Mgt-VMs': ["10.100.1.51", "10.100.1.52", "10.100.1.53", "10.100.1.54", "10.100.1.55", "10.100.1.56", "10.100.1.57", "10.100.1.58", "10.100.1.59", "10.100.1.60", "10.100.1.61", "10.100.1.62", "10.100.1.63", "10.100.1.64", "10.100.1.65", "10.100.1.66", "10.100.1.67", "10.100.1.68", "10.100.1.69", "10.100.1.70", "10.100.1.71", "10.100.1.72", "10.100.1.73", "10.100.1.74", "10.100.1.75", "10.100.1.76", "10.100.1.77", "10.100.1.78", "10.100.1.79", "10.100.1.80", "10.100.1.81", "10.100.1.82", "10.100.1.83", "10.100.1.84", "10.100.1.85", "10.100.1.86", "10.100.1.87", "10.100.1.88", "10.100.1.89", "10.100.1.90", "10.100.1.91", "10.100.1.92", "10.100.1.93", "10.100.1.94", "10.100.1.95", "10.100.1.96", "10.100.1.97", "10.100.1.98", "10.100.1.99", "10.100.1.100", "10.100.1.101", "10.100.1.102", "10.100.1.103", "10.100.1.104", "10.100.1.105", "10.100.1.106", "10.100.1.107", "10.100.1.108", "10.100.1.109", "10.100.1.110", "10.100.1.111", "10.100.1.112", "10.100.1.113", "10.100.1.114", "10.100.1.115", "10.100.1.116", "10.100.1.117", "10.100.1.118", "10.100.1.119", "10.100.1.120", "10.100.1.121", "10.100.1.122", "10.100.1.123", "10.100.1.124", "10.100.1.125", "10.100.1.126", "10.100.1.127", "10.100.1.128", "10.100.1.129", "10.100.1.130", "10.100.1.131", "10.100.1.132", "10.100.1.133", "10.100.1.134", "10.100.1.135", "10.100.1.136", "10.100.1.137", "10.100.1.138", "10.100.1.139", "10.100.1.140", "10.100.1.141", "10.100.1.142", "10.100.1.143", "10.100.1.144", "10.100.1.145", "10.100.1.146", "10.100.1.147", "10.100.1.148", "10.100.1.149", "10.100.1.150", "10.100.1.151", "10.100.1.152", "10.100.1.153", "10.100.1.154", "10.100.1.155", "10.100.1.156", "10.100.1.157", "10.100.1.158", "10.100.1.159", "10.100.1.160", "10.100.1.161", "10.100.1.162", "10.100.1.163", "10.100.1.164", "10.100.1.165", "10.100.1.166", "10.100.1.167", "10.100.1.168", "10.100.1.169", "10.100.1.170", "10.100.1.171", "10.100.1.172", "10.100.1.173", "10.100.1.174", "10.100.1.175", "10.100.1.176", "10.100.1.177", "10.100.1.178", "10.100.1.179", "10.100.1.180", "10.100.1.181", "10.100.1.182", "10.100.1.183", "10.100.1.184", "10.100.1.185", "10.100.1.186", "10.100.1.187", "10.100.1.188", "10.100.1.189", "10.100.1.190", "10.100.1.191", "10.100.1.192", "10.100.1.193", "10.100.1.194", "10.100.1.195", "10.100.1.196", "10.100.1.197", "10.100.1.198", "10.100.1.199", "10.100.1.200", "10.100.1.201", "10.100.1.202", "10.100.1.203", "10.100.1.204", "10.100.1.205", "10.100.1.206", "10.100.1.207", "10.100.1.208", "10.100.1.209", "10.100.1.210", "10.100.1.211", "10.100.1.212", "10.100.1.213", "10.100.1.214", "10.100.1.215", "10.100.1.216", "10.100.1.217", "10.100.1.218", "10.100.1.219", "10.100.1.220", "10.100.1.221", "10.100.1.222", "10.100.1.223", "10.100.1.224", "10.100.1.225", "10.100.1.226", "10.100.1.227", "10.100.1.228", "10.100.1.229", "10.100.1.230", "10.100.1.231", "10.100.1.232", "10.100.1.233", "10.100.1.234", "10.100.1.235", "10.100.1.236", "10.100.1.237", "10.100.1.238", "10.100.1.239", "10.100.1.240", "10.100.1.241", "10.100.1.242", "10.100.1.243", "10.100.1.244", "10.100.1.245", "10.100.1.246", "10.100.1.247", "10.100.1.248", "10.100.1.249", "10.100.1.250", "10.100.1.251", "10.100.1.252", "10.100.1.253", "10.100.1.254"],
    'SDE-Mgt-Oracle-Storage': ['10.100.1.40', '10.100.1.44'],
    'SDE-Mgt-f5': ['10.100.1.50'],
    'SDE-Mgt-Oracle-Exadata': ['10.100.1.28', '10.100.1.29', '10.100.1.30', '10.100.1.31', '10.100.1.32', '10.100.1.33', '10.100.1.34', '10.100.1.35', '10.100.1.36', '10.100.1.41', '10.100.1.42', '10.100.1.43'],
    'SDE-Mgt-Oracle-Servers': ['10.100.1.11', '10.100.1.12', '10.100.1.13', '10.100.1.14', '10.100.1.15', '10.100.1.16', '10.100.1.17', '10.100.1.18', '10.100.1.19', '10.100.1.20', '10.100.1.21', '10.100.1.22', '10.100.1.23', '10.100.1.24', '10.100.1.25', '10.100.1.26', '10.100.1.27', '10.100.1.46', '10.100.1.47'],
    'SDE-Mgt-Oracle-Switches': ['10.100.1.5', '10.100.1.6', '10.100.1.7'],
    'SDE-Mgt-Fortigate': ['10.100.1.1', '10.100.1.2', '10.100.1.3', '10.100.1.4']
}