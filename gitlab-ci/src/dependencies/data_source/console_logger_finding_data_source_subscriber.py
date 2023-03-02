from data_source.finding_data_source_subscriber import FindingDataSourceSubscriber
from model.finding import Finding


class ConsoleLoggerFindingDataSourceSubscriber(FindingDataSourceSubscriber):
    def on_finding_created(self, finding: Finding):
        print(f"on_finding_created({finding})")

    def on_finding_refreshed(self, finding_before: Finding, finding_after: Finding):
        print(f"on_finding_refreshed({finding_before},{finding_after})")

    def on_finding_deleted(self, finding: Finding):
        print(f"on_finding_deleted({finding})")
