import random
import uuid
import hashlib

class EndpointEventGenerator:
    def generate_sysmon_event1(self, timestamp, hostname, image_path, command_line, parent_image, parent_command_line, user, integrity_level='Medium', hash_sha256=None) -> dict:
        process_guid = f"{{{uuid.uuid4()}}}"
        parent_process_guid = f"{{{uuid.uuid4()}}}"
        if not hash_sha256:
            hash_sha256 = hashlib.sha256(image_path.encode()).hexdigest()
        
        return {
            "EventID": 1,
            "UtcTime": timestamp,
            "ProcessGuid": process_guid,
            "ProcessId": random.randint(1000, 10000),
            "Image": image_path,
            "FileVersion": "1.0.0.0",
            "Description": "Executable",
            "Product": "Unknown",
            "Company": "Unknown",
            "OriginalFileName": image_path.split("\\")[-1] if "\\" in image_path else image_path.split("/")[-1],
            "CommandLine": command_line,
            "CurrentDirectory": "C:\\Windows\\System32\\",
            "User": user,
            "LogonGuid": f"{{{uuid.uuid4()}}}",
            "LogonId": f"0x{random.randint(10000, 999999):x}",
            "TerminalSessionId": 1,
            "IntegrityLevel": integrity_level,
            "Hashes": f"SHA256={hash_sha256}",
            "ParentProcessGuid": parent_process_guid,
            "ParentProcessId": random.randint(100, 5000),
            "ParentImage": parent_image,
            "ParentCommandLine": parent_command_line
        }

    def generate_sysmon_event3(self, timestamp, hostname, image_path, user, src_ip, src_port, dst_ip, dst_port, protocol) -> dict:
        return {
            "EventID": 3,
            "UtcTime": timestamp,
            "ProcessGuid": f"{{{uuid.uuid4()}}}",
            "ProcessId": random.randint(1000, 10000),
            "Image": image_path,
            "User": user,
            "Protocol": protocol.lower(),
            "Initiated": "true",
            "SourceIsIpv6": "false",
            "SourceIp": src_ip,
            "SourceHostname": hostname,
            "SourcePort": src_port,
            "SourcePortName": "-",
            "DestinationIsIpv6": "false",
            "DestinationIp": dst_ip,
            "DestinationHostname": dst_ip,
            "DestinationPort": dst_port,
            "DestinationPortName": "-"
        }

    def generate_sysmon_event10(self, timestamp, hostname, source_image, target_image, granted_access, user) -> dict:
        return {
            "EventID": 10,
            "UtcTime": timestamp,
            "SourceProcessGuid": f"{{{uuid.uuid4()}}}",
            "SourceProcessId": random.randint(1000, 10000),
            "SourceThreadId": random.randint(100, 5000),
            "SourceImage": source_image,
            "TargetProcessGuid": f"{{{uuid.uuid4()}}}",
            "TargetProcessId": random.randint(1000, 10000),
            "TargetImage": target_image,
            "GrantedAccess": granted_access,
            "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d8a4",
            "SourceUser": user,
            "TargetUser": "NT AUTHORITY\\SYSTEM"
        }

    def generate_auditd_execve(self, timestamp, hostname, uid, username, exe, command_args, ppid, pid, success=True) -> dict:
        return {
            "type": "EXECVE",
            "timestamp": timestamp,
            "hostname": hostname,
            "uid": uid,
            "euid": uid,
            "username": username,
            "pid": pid,
            "ppid": ppid,
            "exe": exe,
            "argc": len(command_args),
            "args": command_args,
            "success": "yes" if success else "no",
            "res": "success" if success else "failed"
        }

    def generate_windows_7045(self, timestamp, hostname, service_name, service_file, service_type, start_type, account_name) -> dict:
        return {
            "EventID": 7045,
            "Timestamp": timestamp,
            "Computer": hostname,
            "ServiceName": service_name,
            "ImagePath": service_file,
            "ServiceType": service_type,
            "StartType": start_type,
            "AccountName": account_name
        }

    def generate_windows_5140(self, timestamp, hostname, username, domain, share_name, src_ip) -> dict:
        return {
            "EventID": 5140,
            "Timestamp": timestamp,
            "Computer": hostname,
            "SubjectUserSid": f"S-1-5-21-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(1000, 9999)}",
            "SubjectUserName": username,
            "SubjectDomainName": domain,
            "SubjectLogonId": f"0x{random.randint(10000, 999999):x}",
            "ShareName": share_name,
            "SharePath": f"\\??\\C:\\{share_name}",
            "IpAddress": src_ip,
            "IpPort": random.randint(1024, 65535)
        }
