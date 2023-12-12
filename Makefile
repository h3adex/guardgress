.PHONY: azure kind dev

azure:
	sh build/build-azure.sh


kind:
	@sh build/build-kind.sh

dev:
	@if [ "$(target)" = "azure" ]; then \
        $(MAKE) azure; \
    elif [ "$(target)" = "kind" ]; then \
        $(MAKE) kind; \
    else \
        echo "Please specify a valid target: azure or kind"; \
    fi