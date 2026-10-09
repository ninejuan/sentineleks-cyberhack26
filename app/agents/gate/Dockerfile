FROM public.ecr.aws/lambda/python:3.12

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt semgrep==1.180.0 \
    && rm /tmp/requirements.txt

ENV SEMGREP_SEND_METRICS=off \
    SEKS_SEMGREP_RULES=/var/task/rules/semgrep \
    SEKS_SEMGREP_REGISTRY=/var/task/rules/registry/p-kubernetes.yaml

COPY app ${LAMBDA_TASK_ROOT}/app
COPY rules ${LAMBDA_TASK_ROOT}/rules
COPY app/agents/gate/handler.py ${LAMBDA_TASK_ROOT}/handler.py

CMD ["handler.lambda_handler"]
