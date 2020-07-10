FROM fedora:32

RUN dnf update -y
RUN dnf install fedora-packager clang clang-devel nettle python3-devel python3-pip git nettle-devel -y



RUN useradd --create-home --home-dir /home/kdas kdas \
        && chown -R kdas:kdas /home/kdas

USER kdas
WORKDIR /home/kdas

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > install.sh
RUN sh install.sh -y --default-toolchain nightly --component cargo
RUN echo "source ~/.cargo/env" >> ~/.bashrc
RUN python3 -m venv venv
RUN source venv/bin/activate
RUN venv/bin/python3 -m pip install pytest maturin


CMD ["/usr/bin/bash"]
