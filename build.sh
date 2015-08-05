#!/bin/sh
if [ ! -e "ebin/pwd_drv.so" ]; then
	./configure && make
fi
