docker:
	docker build -f deployment/dockerfiles/bridge.Dockerfile -t enigmampc/eth-bridge:0.8.3 .

local-docker:
	docker build -f deployment/dockerfiles/bridge.Dockerfile -t enigmampc/eth-bridge-test:0.0.1 .
