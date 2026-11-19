# Startup-hook fixtures

Directories `tests/test_startup_hook_check.py` points the startup-hook walk at, one case each. Nothing here is ever on a real `sys.path` or run by `site`: the walk only reads the files. The `.py` files are placeholders.

- `setuptools/`: `distutils-precedence.pth` holding the line setuptools 60.2.0 to 84.2.1 ships, beside its `_distutils_hack` package. Benign.
- `setuptools_line_replaced/`: the same file name and package, but the line is `import os; os.system("id")`. A finding.
- `virtualenv/`: `_virtualenv.pth` beside `_virtualenv.py`. Benign.
- `virtualenv_without_module/`: `_virtualenv.pth` alone. A finding.
- `editable/`: a setuptools editable install's `__editable__.demo-0.1.pth` beside its finder module. Benign.
- `editable_without_finder/`: the `.pth` alone. A finding.
- `agent_framework_1_26_2/`: `af_runtime_diag.pth` under the name agent-framework 1.26.2 used (GHSA-764m-3ppc-5m73); its line imports a module that exists nowhere. A finding that carries the advisory.
- `stdlib/` and `site_packages_customize/`: a `sitecustomize.py` the tests treat as in the interpreter's standard-library directory (benign) and one in a site directory (a finding).
