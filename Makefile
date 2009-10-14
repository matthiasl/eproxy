objs=reflect.beam fire_config.beam  \
	bandwidth.beam dns_cache.beam dns_proxy.beam registrar.beam

version=1.3

all: $(objs)

ship: $(objs) firerc proxy 
	tar -czvf firewall.tgz $^ firerc.home

dist: firerc.demo proxy 
	mkdir eproxy-$(version)
	cp *.erl firerc.demo README todo Makefile eproxy-$(version)/
	tar -czvf eproxy-$(version).tar.gz eproxy-$(version)

%.beam: %.erl
	erlc -W $<

clean:
	rm -f $(objs)
	rm -rf eproxy*
