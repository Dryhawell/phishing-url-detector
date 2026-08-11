# Common developer commands

Works with GNU Make (Git Bash / WSL / macOS / Linux).
On Windows PowerShell you can run the same commands manually.

```bash
make install      # pip install -e ".[dev]"
make test         # pytest
make run          # GUI
make api          # local API on 127.0.0.1:8765
make batch        # sample batch analysis
make assets       # regenerate icons + screenshot
make exe          # PyInstaller one-file build
```

```makefile
.PHONY: install test run api batch assets exe clean

install:
	python -m pip install --upgrade pip
	pip install -e ".[dev]"

test:
	python -m pytest tests -q --tb=short

run:
	python main.py

api:
	python main.py --api

batch:
	python main.py --batch samples/urls.txt

assets:
	python scripts/generate_assets.py

exe:
	python scripts/build_exe.py

clean:
	rm -rf build dist .pytest_cache **/__pycache__
```
