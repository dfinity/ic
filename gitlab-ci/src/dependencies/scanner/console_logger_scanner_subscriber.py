from scanner.scanner_job_type import ScannerJobType
from scanner.scanner_subscriber import ScannerSubscriber


class ConsoleLoggerScannerSubscriber(ScannerSubscriber):
    def on_merge_request_blocked(self, job_id: str, merge_request_id: str):
        print(f"on_merge_request_blocked({job_id},{merge_request_id})")

    def on_release_build_blocked(self, job_id: str):
        print(f"on_release_build_blocked({job_id})")

    def on_scan_job_succeeded(self, job_type: ScannerJobType, job_id: str):
        print(f"on_scan_job_succeeded({job_type.name},{job_id})")

    def on_scan_job_failed(self, job_type: ScannerJobType, job_id: str, reason: str):
        print(f"on_ci_job_failed({job_type.name},{job_id},{reason})")
