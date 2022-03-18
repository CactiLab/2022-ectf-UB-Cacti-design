#! /bin/bash
set -e
set -m

if [ $# -ne 3 ]; then
echo "usage: ./auto_run.sh [SYS_NAME] [UART_SOCK]"
echo "example: ./auto_run.sh saffire-xi 1337"
fi

SYS_NAME=$1
UART_SOCK=$2

echo saffire-xi
echo 1337

docker volume create saffire-xi-flash.vol
docker volume create saffire-xi-eeprom.vol
docker volume create saffire-xi-secrets.vol

if [ -d "socks" ]; then
    echo "recreate socks folder..." 
    rm -rf socks
#     mkdir socks
#     echo "create socks folder.."
fi

# 1. Building the Deployment
# echo ""
python tools/run_saffire_win.py build-system --physical    --sysname saffire-xi    --oldest-allowed-version 1

# 2. Launch the Bootloader
python tools/run_saffire_win.py load-device --physical --sysname saffire-xi

python tools/run_saffire_win.py launch-bootloader --physical  --sysname saffire-xi --sock-root socks/ --uart-sock 1337 --serial-port COM5

# python3 tools/run_saffire_win.py launch-bootloader --emulated --sysname saffire-xi --sock-root socks/ --uart-sock 1337

# 3. Protect the SAFFIRe Files
python tools/run_saffire_win.py fw-protect --physical     --sysname saffire-xi     --fw-root firmware/     --raw-fw-file example_fw.bin     --protected-fw-file example_fw.prot     --fw-version 2     --fw-message 'hello world'

python tools/run_saffire_win.py cfg-protect --physical     --sysname saffire-xi     --cfg-root configuration/     --raw-cfg-file example_cfg.bin     --protected-cfg-file example_cfg.prot


# # 4. Update and Load the Bootloader

# python3 /host_tools/cfg_load --socket 1337 --config-file example_cfg.prot
python tools/run_saffire_win.py fw-update --physical     --sysname saffire-xi     --fw-root firmware/     --uart-sock 1337     --protected-fw-file example_fw.prot


python tools/run_saffire_win.py cfg-load --physical     --sysname saffire-xi     --cfg-root configuration/     --uart-sock 1337     --protected-cfg-file example_cfg.prot

# # 5. Readback
python tools/run_saffire_win.py fw-readback --physical     --sysname saffire-xi     --uart-sock 1337     --rb-len 100

python tools/run_saffire_win.py cfg-readback --physical     --sysname saffire-xi     --uart-sock 1337     --rb-len 100

# # 6. Boot firmware
python tools/run_saffire_win.py boot --physical    --sysname saffire-xi    --uart-sock 1337    --boot-msg-file boot.txt
python tools/run_saffire_win.py monitor --physical    --sysname saffire-xi    --uart-sock 1337    --boot-msg-file boot.txt

# # 7. Shutting Down the Bootloader
python tools/run_saffire_win.py kill-system --physical --sysname saffire-xi

