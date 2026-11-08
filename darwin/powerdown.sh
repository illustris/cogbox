# ARM virt has a GPIO power button. Upstream microvm-shutdown now sends the
# same system_powerdown; this script stays darwin's helper. Request the power
# button once and wait for QEMU to exit.
printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"system_powerdown"}' |
    socat STDIO UNIX:cogbox.socket,shut-none
while socat -u /dev/null UNIX:cogbox.socket 2>/dev/null; do
    sleep 1
done
