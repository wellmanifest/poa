FROM python:3.12.10-alpine3.21

WORKDIR /workspace

COPY standard/ /workspace/standard/

USER 65532:65532

ENTRYPOINT ["python", "/workspace/standard/conformance.py"]
CMD ["--all"]
