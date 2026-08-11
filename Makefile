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
	python -c "import shutil, pathlib; [shutil.rmtree(p, ignore_errors=True) for p in ('build','dist','.pytest_cache')];\
[shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]"
