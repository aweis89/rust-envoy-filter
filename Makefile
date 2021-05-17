.PHONY: build

build:
	cargo build --target wasm32-unknown-unknown --release --lib
	cp ./target/wasm32-unknown-unknown/release/cargo.wasm ./filter.wasm

cm: build
	kubectl create cm filter --from-file=filter.wasm
