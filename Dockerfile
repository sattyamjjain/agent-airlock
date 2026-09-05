# syntax=docker/dockerfile:1
#
# Sandbox execution image for the four `docker`-marked tests in
# tests/test_sandbox_backend_docker_integration.py.
#
# WHY THIS IMAGE EXISTS
# ---------------------
# Those tests drive DockerBackend, which serializes a callable with
# cloudpickle and runs `python -c <script>` inside a container with
# `network_mode="none"`. Two consequences make the stock
# `python:3.11-slim` image insufficient, and both are load-bearing:
#
#   1. The generated in-container script starts with `import cloudpickle`.
#      With no network the container cannot pip-install it at run time, so
#      cloudpickle has to be baked in.
#   2. cloudpickle serializes the test helpers **by reference**, not by
#      value — the payload is ~111 bytes carrying the string
#      "tests.test_sandbox_backend_docker_integration". Unpickling
#      therefore imports that module inside the container, which in turn
#      imports `pytest` and `agent_airlock.sandbox_backend`. So the image
#      needs the package, pytest, and the tests/ package on sys.path.
#
# Build (tag must match AIRLOCK_DOCKER_TEST_IMAGE, default below):
#   docker build -t agent-airlock-sandbox:local .
#
# Then:
#   pytest -m docker
#
# Keep PYTHON_VERSION aligned with the interpreter running pytest on the
# host. cloudpickle's by-reference payloads are tolerant across minor
# versions, but pinning both sides removes the variable entirely.
ARG PYTHON_VERSION=3.11
FROM python:${PYTHON_VERSION}-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Package metadata + sources first so the dependency layer caches
# independently of test edits.
COPY pyproject.toml README.md LICENSE* ./
COPY src/ ./src/

# `.` pulls the Pydantic-only core (see scripts/check_core_deps.py).
# cloudpickle and pytest are execution-side requirements of the sandbox
# payload, not runtime dependencies of the library — deliberately not
# added to pyproject.
RUN pip install --no-cache-dir . cloudpickle pytest

# tests/ is a real package (tests/__init__.py), which is what makes the
# by-reference unpickle resolve.
COPY tests/ ./tests/

# The backend already runs containers with cap_drop=ALL and
# no-new-privileges; dropping root as well costs nothing here.
RUN useradd --create-home --uid 10001 sandbox \
    && chown -R sandbox:sandbox /app
USER sandbox

# Fail the build rather than a test if the import chain the sandbox
# depends on is broken.
RUN python -c "import cloudpickle, pytest, agent_airlock.sandbox_backend; \
import tests.test_sandbox_backend_docker_integration as m; \
assert m._trivial_success(2, 3) == 5; print('sandbox image import chain OK')"

CMD ["python", "-c", "print('agent-airlock sandbox image; driven by DockerBackend')"]
