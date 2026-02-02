FROM python:3.12-slim

ARG ANSIBLE_CORE_VERSION=2.16.6
ARG ANSIBLE_GALAXY_COLLECTIONS=""

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      dnsutils \
      git \
      iproute2 \
      iputils-ping \
      netcat-openbsd \
      openssh-client \
      openssh-server \
      sshpass \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
      "ansible-core==${ANSIBLE_CORE_VERSION}" \
      ncclient \
      jmespath

RUN if [ -n "$ANSIBLE_GALAXY_COLLECTIONS" ]; then \
      mkdir -p /usr/share/ansible/collections && \
      ansible-galaxy collection install $ANSIBLE_GALAXY_COLLECTIONS -p /usr/share/ansible/collections; \
    fi

RUN useradd -m -u 10001 ansible \
    && mkdir -p /var/run/sshd /home/ansible/.ssh \
    && chown -R ansible:ansible /home/ansible/.ssh \
    && chmod 700 /home/ansible/.ssh \
    && touch /home/ansible/.ssh/authorized_keys \
    && chmod 600 /home/ansible/.ssh/authorized_keys \
    && printf '%s\n' \
      'PasswordAuthentication no' \
      'PermitRootLogin no' \
      'PubkeyAuthentication yes' \
      'AllowUsers ansible' \
      > /etc/ssh/sshd_config.d/nck.conf

# Bake the example Ansible workspace into the image for a no-mount workflow.
COPY --chown=ansible:ansible image/ansible-config /work

# Non-root user for safer defaults
USER ansible
WORKDIR /work

ENTRYPOINT ["ansible-playbook"]
CMD ["--version"]

EXPOSE 22
