.PHONY: scan test lint fmt deploy clean tf-init tf-plan tf-apply tf-destroy

scan:
	python main.py

test:
	pytest tests/ -v

lint:
	flake8 sentinel/ main.py

fmt:
	black sentinel/ main.py

# Run before 'terraform apply' to build the Lambda zip
deploy:
	mkdir -p build
	zip -r build/sentinel-auditor.zip main.py sentinel/ --exclude "**/__pycache__/*" "**/*.pyc"

clean:
	rm -rf build/ __pycache__/ .pytest_cache/ sentinel/__pycache__/

tf-init:
	cd infra/environments/personal && terraform init

tf-plan:
	cd infra/environments/personal && terraform plan

tf-apply:
	cd infra/environments/personal && terraform apply

tf-destroy:
	cd infra/environments/personal && terraform destroy