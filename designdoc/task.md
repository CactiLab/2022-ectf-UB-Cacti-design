## Date: 02/08/2022

---

### Blue team

|               Task               |                                                      Description                                                                              |    Implementation tools|     Assigned     |
|----------|:-------------:|------:|------:|             
| MPU configuration at Boot loader |  Configure memory regions of bootloader, firmware, configuration data. The goal here is to make the bootloader region safe from unauthorized access. |C|  Xi |
| EEPROM to protect secret data    |  Configure the EEPROM security settings to protect secret data from unauthorized access. (Figure out which feature to use)   |C|Tomal |
| Host Authentication (RSA): host tools  |  Implement the digital signature design described in the document to authenticate the host for readback. Should output the public key for the bootloader. | Python, Docker| Qiqing |
| Host Authentication (RSA): bootloader  |  Implement the digital signature verification described in the document. The public key should be compiled inside the bootloader. (Maybe as a header file) |   C  | Qiqing |
| Protected firmware, configuration image (AES-GCM): host tools  |  Modify the python host tools to encrypt the firmware, output the secrets, and put it on the docker images. The secrets should be put into the EEPROM as binary data |  Python, Docker   | Tomal: DONE |
| Protected firmware, configuration image (AES-GCM): bootloader  |  Modify the bootloader source code to ensure the authenticity and integrity of protected images. The keys should be read from the EEPROM memory regions at runtime |   C  | Tomal: DONE|
| Reverse engineering challenges |  Solve the reverse engineering challenges when released | * | * |
| Side-channel attack challenges |  Solve the side-channel attack challenges when released | *  | * |

**ATTENTION**: Crypto library selection (bit, license). 

---

### Red team

|               Task               |                                                      Description                                                                              |    Implementation tools|     Assigned     |
|----------|:-------------:|------:|------:|    
| Flash trojan |  Figure out how can we insert the flash trojan, how it is triggered, capabilities. |C|   |
| Reverse engineering |  |     | |  
| Side-channel attack |  |     | |  
| Brute-force the password for host authentication |  |     | |       