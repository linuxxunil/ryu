VER=3.20

DIST-PACKAGES-PATH=/usr/local/lib/python2.7/dist-packages
PWD=$(shell pwd)

all:install_python install_package install_ryu install_exe
install_python:
	apt-get install python-routes python-webob python-paramiko python-pkg-resources #python-eventlet
install_ryu:
	#cp -af ryu-3.20 $(DIST-PACKAGES-PATH)
	#cp -af ryu-3.20.egg-info $(DIST-PACKAGES-PATH)
	#cp -af ryu-3.26 $(DIST-PACKAGES-PATH)
	#cp -af ryu-3.26.egg-info $(DIST-PACKAGES-PATH)
	rm -rf $(DIST-PACKAGES-PATH)/ryu
	rm -rf $(DIST-PACKAGES-PATH)/ryu-$(VER).egg-info
	ln -sf $(PWD)/ryu-$(VER) $(DIST-PACKAGES-PATH)/ryu
	ln -sf $(PWD)/ryu-$(VER).egg-info $(DIST-PACKAGES-PATH)/ryu-$(VER).egg-info

install_package:
	#eventlet
	cp -af eventlet $(DIST-PACKAGES-PATH)
	cp -af eventlet-0.17.4.dist-info $(DIST-PACKAGES-PATH)
	#oslo
	cp -af oslo $(DIST-PACKAGES-PATH)
	cp -af oslo_config $(DIST-PACKAGES-PATH)
	cp -af oslo.config-1.12.1.dist-info $(DIST-PACKAGES-PATH)
	cp -af oslo.config-1.12.1-py2.7-nspkg.pth $(DIST-PACKAGES-PATH)
	#markerlib
	cp -af markerlib $(DIST-PACKAGES-PATH)
	cp -af _markerlib $(DIST-PACKAGES-PATH)
	cp -af markerlib-0.6.0.dist-info $(DIST-PACKAGES-PATH)
	#netaddr
	cp -af netaddr $(DIST-PACKAGES-PATH)
	cp -af netaddr-0.7.14.dist-info $(DIST-PACKAGES-PATH)
	#msgpack
	cp -af msgpack $(DIST-PACKAGES-PATH)
	cp -af msgpack_python-0.4.6.dist-info $(DIST-PACKAGES-PATH)
	#stevedore
	cp -af stevedore $(DIST-PACKAGES-PATH)
	cp -af stevedore-1.5.0.dist-info $(DIST-PACKAGES-PATH)
	#six
	cp -af six.py $(DIST-PACKAGES-PATH)
	cp -af six-1.9.0.dist-info $(DIST-PACKAGES-PATH)
	#pbr
	cp -af pbr $(DIST-PACKAGES-PATH)
	cp -af pbr-1.2.0.dist-info $(DIST-PACKAGES-PATH)
	#greenlet
	cp -af greenlet.so $(DIST-PACKAGES-PATH)
	cp -af greenlet-0.4.9.egg-info $(DIST-PACKAGES-PATH)
install_exe:
	cp -f script/ryu-3.20 /usr/local/bin
	cp -f script/ryu-manager-3.20 /usr/local/bin
	cp -f script/ryu-3.26 /usr/local/bin
	cp -f script/ryu-manager-3.26 /usr/local/bin
	ln -sf /usr/local/bin/ryu-$(VER) /usr/local/bin/ryu
	ln -sf /usr/local/bin/ryu-manager-$(VER) /usr/local/bin/ryu-manager
clean:

