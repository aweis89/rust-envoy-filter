FROM docker.jfrog.skillz.com/istio/proxyv2:1.9.0

ADD ./filter.wasm /var/local/lib/wasm-filters/filter.wasm
