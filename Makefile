.PHONY: install test demo dashboard run compliance bom clean

install:            ## Python + dashboard dependencies
	pip install -r requirements.txt
	cd dashboard && npm install

test:               ## unit + integration tests (no hardware needed)
	python -m pytest tests -q

dashboard:          ## build the operator UI into dashboard/dist
	cd dashboard && npm run build

demo: dashboard     ## full system on simulated traffic at http://127.0.0.1:8000
	python scripts/run_demo.py

run:                ## the real thing (after scripts/init_device.py)
	PYTHONPATH=src python -m vrs.app

compliance:         ## which technical controls are on under the strict profile
	python scripts/compliance_check.py config/compliance.yaml

bom:                ## screen config/hardware_bom.yaml against NDAA Section 889
	python scripts/check_bom.py

clean:
	rm -rf data-demo .pytest_cache dashboard/dist
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
