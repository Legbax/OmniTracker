#!/sbin/sh
# customize.sh - executed by Magisk/KernelSU during installation

ui_print "- Installing Zygisk Telemetry Sniffer module"

# Set up module directories and permissions
ui_print "- Setting permissions..."
set_perm_recursive $MODPATH 0 0 0755 0644

ui_print "- Done!"
