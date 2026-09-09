# ARM virt has a GPIO power button. The upstream Ctrl-Alt-Delete helper needs
# a keyboard absent from this machine, and held keys can trigger systemd's
# emergency reboot. Request the power button once and wait for QEMU to exit.
printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"system_powerdown"}' |
    socat STDIO UNIX:cogbox.socket,shut-none
while socat -u /dev/null UNIX:cogbox.socket 2>/dev/null; do
    sleep 1
done
