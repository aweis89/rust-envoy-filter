.PHONY: build

build:
	#cargo build --target wasm32-unknown-unknown --release
	#cp ./target/wasm32-unknown-unknown/release/cargo.wasm ./filter.wasm
	cargo build --target wasm32-wasi --release
	cp ./target/wasm32-wasi/release/cargo.wasm ./filter.wasm

cm: build
	kubectl create cm filter --from-file=filter.wasm
