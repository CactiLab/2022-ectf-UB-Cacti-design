# add all source files
SRCS = $(wildcard *.c)
OBJS = $(SRCS: .c = .o)

# set compiler
# CC = x86_64-linux-gnu-gcc
# CFLAGS = -O2 -w -m32 -static

# set compile list
# OUTPUT1 = auth
OUTPUT2 = keygen
# OUTPUT3 = test
OUTPUT4 = sign

# all in one list
OUTPUTLIST = $(OUTPUT1) $(OUTPUT2) $(OUTPUT3) $(OUTPUT4)

all : $(OUTPUTLIST)

# compiler targets
$(OUTPUT1) : $(OBJS)
	@$(CC) $^ -o $@ -D_$(shell echo $(@)|tr a-z A-Z)_

$(OUTPUT2) : $(OBJS)
	@$(CC) $^ -o $@ -D_$(shell echo $(@)|tr a-z A-Z)_

$(OUTPUT3) : $(OBJS)
	@$(CC) $^ -o $@ -D_$(shell echo $(@)|tr a-z A-Z)_

$(OUTPUT4) : $(OBJS)
	@$(CC) $^ -o $@ -D_$(shell echo $(@)|tr a-z A-Z)_

%.o : %.c
	@$(CC) -c $< $(CCFLAGS) $(IPATH)

clean:
	@rm $(OUTPUTLIST) host_publicKey* host_privateKey* challenge_*
	# @rm $(OUTPUTLIST)
.PHONY:clean
