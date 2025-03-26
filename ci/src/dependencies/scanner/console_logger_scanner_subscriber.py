from scanner.scanner_job_type import ScannerJobType
from scanner.scanner_subscriber import ScannerSubscriber


class ConsoleLoggerScannerSubscriber(ScannerSubscriber):
    def on_merge_request_blocked(self, scanner_id: str, job_id: str, merge_request_id: str):
        print(f"on_merge_request_blocked({scanner_id},{job_id},{merge_request_id})")

    def on_release_build_blocked(self, scanner_id: str, job_id: str):
        print(f"on_release_build_blocked({scanner_id},{job_id})")

    def on_scan_job_succeeded(self, scanner_id: str, job_type: ScannerJobType, job_id: str):
        print(f"on_scan_job_succeeded({scanner_id},{job_type.name},{job_id})")

    def on_scan_job_failed(self, scanner_id: str, job_type: ScannerJobType, job_id: str, reason: str):
        print(f"on_scan_job_failed({scanner_id},{job_type.name},{job_id},{reason})")
