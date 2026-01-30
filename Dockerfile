FROM python:3.12-slim

ARG ANSIBLE_CORE_VERSION=2.16.6

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      git \
      openssh-client \
      sshpass \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
      "ansible-core==${ANSIBLE_CORE_VERSION}" \
      ncclient \
      jmespath

RUN ansible-galaxy collection install ansible.netcommon

# Non-root user for safer defaults
RUN useradd -m -u 10001 ansible
USER ansible
WORKDIR /work

ENTRYPOINT ["ansible-playbook"]
CMD ["--version"]
