import random
import uuid

class AuthLogGenerator:
    def generate_windows_4624(self, timestamp, src_ip, src_port, dst_ip, username, domain, logon_type, auth_package='Kerberos') -> dict:
        pid = f"0x{random.randint(100, 5000):x}"
        return {
            "EventID": 4624,
            "Timestamp": timestamp,
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": f"{dst_ip}$",
            "SubjectDomainName": domain,
            "SubjectLogonId": "0x3e7",
            "TargetUserSid": f"S-1-5-21-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(1000, 9999)}",
            "TargetUserName": username,
            "TargetDomainName": domain,
            "TargetLogonId": f"0x{random.randint(10000, 999999):x}",
            "LogonType": logon_type,
            "LogonProcessName": "User32",
            "AuthenticationPackageName": auth_package,
            "WorkstationName": "WORKSTATION",
            "LogonGuid": str(uuid.uuid4()),
            "TransmittedServices": "-",
            "LmPackageName": "-",
            "KeyLength": 0,
            "ProcessId": pid,
            "ProcessName": r"C:\Windows\System32\svchost.exe",
            "IpAddress": src_ip,
            "IpPort": src_port,
            "Computer": dst_ip
        }
        
    def generate_windows_4625(self, timestamp, src_ip, src_port, dst_ip, username, domain, logon_type, sub_status='0xC000006A', auth_package='NTLM') -> dict:
        pid = f"0x{random.randint(100, 5000):x}"
        return {
            "EventID": 4625,
            "Timestamp": timestamp,
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": f"{dst_ip}$",
            "SubjectDomainName": domain,
            "SubjectLogonId": "0x3e7",
            "TargetUserSid": "S-1-0-0",
            "TargetUserName": username,
            "TargetDomainName": domain,
            "Status": "0xC000006D",
            "FailureReason": "%%2313",
            "SubStatus": sub_status,
            "LogonType": logon_type,
            "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": auth_package,
            "WorkstationName": "WORKSTATION",
            "TransmittedServices": "-",
            "LmPackageName": "-",
            "KeyLength": 0,
            "ProcessId": pid,
            "ProcessName": r"C:\Windows\System32\svchost.exe",
            "IpAddress": src_ip,
            "IpPort": src_port,
            "Computer": dst_ip
        }

    def generate_windows_4672(self, timestamp, username, domain, hostname, privileges) -> dict:
        return {
            "EventID": 4672,
            "Timestamp": timestamp,
            "SubjectUserSid": f"S-1-5-21-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(1000, 9999)}",
            "SubjectUserName": username,
            "SubjectDomainName": domain,
            "SubjectLogonId": f"0x{random.randint(10000, 999999):x}",
            "PrivilegeList": "\n".join(privileges),
            "Computer": hostname
        }

    def generate_windows_4769(self, timestamp, src_ip, username, service_name, ticket_encryption='0x12', result='0x0') -> dict:
        return {
            "EventID": 4769,
            "Timestamp": timestamp,
            "TargetUserName": username,
            "TargetDomainName": "DOMAIN.LOCAL",
            "ServiceName": service_name,
            "ServiceSid": f"S-1-5-21-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(1000, 9999)}",
            "TicketOptions": "0x40810000",
            "TicketEncryptionType": ticket_encryption,
            "IpAddress": src_ip,
            "IpPort": random.randint(1024, 65535),
            "Status": result,
            "LogonGuid": str(uuid.uuid4()),
            "TransmittedServices": "-"
        }
        
    def generate_linux_auth_log(self, timestamp, hostname, service, message, src_ip=None, username=None) -> dict:
        pid = random.randint(100, 30000)
        return {
            "timestamp": timestamp,
            "hostname": hostname,
            "service": service,
            "pid": pid,
            "message": message,
            "src_ip": src_ip,
            "username": username
        }
