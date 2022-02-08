## Date: 02/08/2022

    Blue team
Task List:
|               Task               |                                                      Description                                                                              |    Implementation tools|     Assigned     |
|----------|:-------------:|------:|------:|             
| MPU configuration at Boot loader |  Configure memory regions of bootloader, firmware, configuration data. The goal here is to make the bootloader region safe from unauthorized access. |C|  Xi |
| EEPROM to protect secret data    |  Configure the EEPROM security settings to protect secret data from unauthorized access. (Figure out which feature to use)   |C|Tomal |
| Host Authentication: host tools  |  Implement the digital signature design described in the document to authenticate the host for readback. Should output the public key for the bootloader. | Python, Docker| |
| Host Authentication: bootloader  |  Implement the digital signature verification described in the document. The public key should be compiled inside the bootloader. (Maybe as a header file) |   C  | |
| Protected firmware, configuration image: host tools  |  Modify the python host tools to encrypt the firmware, output the secrets, and put it on the docker images. The secrets should be put into the EEPROM as binary data |  Python, Docker   |
| Protected firmware, configuration image: bootloader  |  Modify the bootloader source code to ensure the authenticity and integrity of protected images. The keys should be read from the EEPROM memory regions at runtime |   C  | |
| Reverse engineering challenges |  Solve the reverse engineering challenges when released |     | |
| Side-channel attack challenges |  Solve the side-channel attack challenges when released |     | |


    Red team
Task List:
|               Task               |                                                      Description                                                                              |    Implementation tools|     Assigned     |
|----------|:-------------:|------:|------:|             
| Flash trojan |  Figure out how can we insert the flash trojan, how it is triggered, capabilities. |C|   |