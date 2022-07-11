.PHONY: clean

all: tpm2_axiado_server

tpm2_axiado_server: tpm2_axiado_server.c tpm2_axiado.c
	gcc tpm2_axiado_server.c tpm2_axiado.c -I$(PWD) -I$(PWD)/../tpm2_shared -g -lcrypto -o tpm2_axiado_server

clean:
	rm -f tpm2_axiado_server
