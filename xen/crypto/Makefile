obj-y += rijndael.o
obj-y += vmac.o
obj-$(CONFIG_PAYLOAD_SIGNING) += sha256.o
obj-$(CONFIG_PAYLOAD_SIGNING) += rsa.o
obj-$(CONFIG_PAYLOAD_SIGNING) += builtin_payload_key.o

ifeq ($(CONFIG_PAYLOAD_SIGNING),y)
key_path = $(patsubst "%",%,$(CONFIG_PAYLOAD_SIG_KEY))
builtin_payload_key.bin: $(key_path) $(BASEDIR)/tools/extract-key.py FORCE
	$(PYTHON) $(BASEDIR)/tools/extract-key.py < $< > $@.new
	$(call move-if-changed,$@.new,$@)

builtin_payload_key.o: builtin_payload_key.bin
endif
