"""S6: a test service that joins at runtime in the demo. It is not one of the five required services."""
from scanner_kit import Adapter, Finding, Result


class TestAdapter(Adapter):
    id = "s6"
    name = "Test Scanner (demo only)"
    description = "Counts submitted files. It exists to demonstrate a service joining and leaving at runtime."
    capabilities = ["test", "demo"]
    tool = None

    def scan(self, ctx):
        return Result("complete", [Finding("file-count", "info", "", "request", f"Received {len(ctx.files)} file(s)")])
