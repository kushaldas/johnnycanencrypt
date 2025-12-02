#!/bin/bash
set -x

yum install -y nettle clang clang-devel nettle-devel pcsc-lite-devel pcsc-lite-libs

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
export PATH="$HOME/.cargo/bin:$PATH"

curl -LsSf https://astral.sh/uv/install.sh | sh
uv venv --python /opt/python/cp314-cp314/bin/python3.14 /opt/venv
source /opt/venv/bin/activate
uv pip install --upgrade "maturin>=1,<2" -r /io/requirements-dev.txt
cd /io/
maturin build --release --manylinux --sdist
mkdir dist/
echo "Now we need to fix the libpcsc as Debian/Ubuntu/Fedora needs to load system's current library."
for whl in target/wheels/johnnycanencrypt*cp310*-manylinux*.whl; do
	mkdir wtest
	unzip "$whl" -d wtest/
	patchelf --replace-needed libpcsclite-a573614e.so.1 libpcsclite.so.1 wtest/johnnycanencrypt/johnnycanencrypt.abi3.so
	wheel pack --dest-dir ./dist/ wtest
	rm -rf wtest
done
echo "Let us copy the source tarball"
cp target/wheels/johnnycanencrypt*.tar.gz ./dist/
