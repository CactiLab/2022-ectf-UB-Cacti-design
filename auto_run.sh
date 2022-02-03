#! /bin/bash
set -e
set -m

if [ $# -ne 3 ]; then
echo "usage: ./auto_run.sh [SYS_NAME] [UART_SOCK]"
echo "example: ./auto_run.sh saffire-test 1337"
fi

SYS_NAME=$1
UART_SOCK=$2

echo $SYS_NAME
echo $UART_SOCK

docker volume create $SYS_NAME-flash.vol
docker volume create $SYS_NAME-eeprom.vol

# 1. Building the Deployment
# echo ""
python3 tools/run_saffire.py build-system --emulated \
    --sysname $SYS_NAME \
    --oldest-allowed-version 1

# 2. Launch the Bootloader
python3 tools/run_saffire.py load-device --emulated --sysname $SYS_NAME

if [ -d "socks" ]; then
    echo "recreate socks folder..." 
    rm -rf socks
    mkdir socks
    echo "create socks folder.."
fi

python3 tools/run_saffire.py launch-bootloader --emulated  \
    --sysname $SYS_NAME \
    --sock-root socks/ \
    --uart-sock $UART_SOCK
# python3 tools/run_saffire.py launch-bootloader --emulated  \
#     --sysname $SYS_NAME \
#     --sock-root socks/ \
#     --uart-sock $UART_SOCK

# # 3. Protect the SAFFIRe Files
# python3 tools/run_saffire.py fw-protect --emulated \
#     --sysname $SYS_NAME \
#     --fw-root firmware/ \
#     --raw-fw-file example_fw.bin \
#     --protected-fw-file example_fw.prot \
#     --fw-version 2 \
#     --fw-message 'hello world'

# python3 tools/run_saffire.py cfg-protect --emulated \
#     --sysname $SYS_NAME \
#     --cfg-root configuration/ \
#     --raw-cfg-file example_cfg.bin \
#     --protected-cfg-file example_cfg.prot

# # 4. Update and Load the Bootloader
# python3 tools/run_saffire.py fw-update --emulated \
#     --sysname $SYS_NAME \
#     --fw-root firmware/ \
#     --uart-sock $UART_SOCK \
#     --protected-fw-file example_fw.prot
# python3 tools/run_saffire.py cfg-load --emulated \
#     --sysname $SYS_NAME \
#     --cfg-root configuration/ \
#     --uart-sock $UART_SOCK \
#     --protected-cfg-file example_cfg.prot

# # 5. Readback
# python3 tools/run_saffire.py fw-readback --emualted \
#     --sysname $SYS_NAME \
#     --uart-sock $UART_SOCK \
#     --rb-len 100
# python3 tools/run_saffire.py cfg-readback --emulated \
#     --sysname $SYS_NAME \
#     --uart-sock $UART_SOCK \
#     --rb-len 100

# # 6. Boot firmware
# python3 tools/run_saffire.py boot --emulated \
#     --sysname $SYS_NAME \
#     --uart-sock $UART_SOCK \
#     --boot-msg-file boot.txt
# python3 tools/run_saffire.py monitor --emulated \
#     --sysname $SYS_NAME \
#     --uart-sock $UART_SOCK \
#     --boot-msg-file boot.txt

# # 7. Shutting Down the Bootloader
# python3 tools/run_saffire.py kill-system --emulated --sysname $SYS_NAME