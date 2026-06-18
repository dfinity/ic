"""
Override a few components for multi-hostos
"""

load("hostos.bzl", hostos_component_files = "component_files")

component_files = hostos_component_files | {
    Label("multi-hostos/start-guestos.sh"): "/opt/ic/bin/start-guestos.sh",
    Label("multi-hostos/start-guestos.service"): "/etc/systemd/system/start-guestos.service",
    Label("multi-hostos/guestos@.service"): "/etc/systemd/system/guestos@.service",
    Label("multi-hostos/verbose-logging.service"): "/etc/systemd/system/verbose-logging.service",
    Label("multi-hostos/monitor-guestos.service"): "/etc/systemd/system/monitor-guestos.service",
    Label("multi-hostos/update-config.service"): "/etc/systemd/system/update-config.service",
}
component_files.pop(Label("hostos/guestos/guestos.service"))
component_files.pop(Label("hostos/verbose-logging/verbose-logging.service"))
component_files.pop(Label("monitoring/hostos/monitor-guestos.service"))
component_files.pop(Label("hostos/update-config/update-config.service"))
component_files.pop(Label("misc/vsock/vsock-agent.service"))
component_files.pop(Label("misc/vsock/10-vhost-vsock.rules"))
