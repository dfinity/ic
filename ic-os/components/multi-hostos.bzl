"""
Override a few components for multi-hostos
"""

load("hostos.bzl", hostos_component_files = "component_files")

component_files = hostos_component_files | {
    Label("multi-hostos/guestos1.service"): "/etc/systemd/system/guestos1.service",
    Label("multi-hostos/guestos2.service"): "/etc/systemd/system/guestos2.service",
    Label("multi-hostos/guestos3.service"): "/etc/systemd/system/guestos3.service",
    Label("multi-hostos/guestos4.service"): "/etc/systemd/system/guestos4.service",
    Label("multi-hostos/guestos5.service"): "/etc/systemd/system/guestos5.service",
    Label("multi-hostos/guestos.target"): "/etc/systemd/system/guestos.target",
    Label("multi-hostos/verbose-logging.service"): "/etc/systemd/system/verbose-logging.service",
    Label("multi-hostos/monitor-guestos.service"): "/etc/systemd/system/monitor-guestos.service",
    Label("multi-hostos/update-config.service"): "/etc/systemd/system/update-config.service",
}
