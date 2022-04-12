#!/usr/bin/python3 -u

# UMASS, Texas, flight abort and version rollback
# UCI flight abort

from json.tool import main


test_file = "test.bin"
# replace the name of the origin_file
origin_file = test_file
crashed_file = "crashed_file.bin"
tmp = b''
data = b''
BLOCK_SIZE=1024

def test():
    try:
        with open(test_file, "wb") as fd:
            data = b'a'*BLOCK_SIZE+b'b'*BLOCK_SIZE+b'c'*BLOCK_SIZE+b'd'*BLOCK_SIZE*2
            fd.write(data)
            print("Gnereate test done...\n")
    except IOError:
        print("Failed to open the file: " + test_file)

def attack():
    try:
        with open(origin_file, "rb") as file:
            # Print the success message
            data = file.read()

            tmp = data[:BLOCK_SIZE]
            tmp += data[BLOCK_SIZE*2:BLOCK_SIZE*3]
            tmp += data[BLOCK_SIZE:BLOCK_SIZE*2]
            tmp += data[BLOCK_SIZE*3:]

            try:
                with open(crashed_file, "wb") as fd:
                    fd.write(tmp)
                    print("Write crashed data back done...\n")
            except IOError:
                print("Failed to open the file: " + crashed_file)

    # Raise error if the file is opened before
    except IOError:
        print("Failed to open the file: " + origin_file)

def main():
    # test()
    attack()

if __name__ == "__main__":
    main()