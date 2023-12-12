FROM golang:1.21.5-alpine as builder
RUN apk --update add ca-certificates tzdata
WORKDIR /app
COPY . ./
RUN go get -v -t -d ./...
RUN go build cmd/server/main.go

FROM scratch
ENV TZ=Europe/Berlin

LABEL org.opencontainers.image.source="https://github.com/h3adex/guardgress"
LABEL org.opencontainers.image.description="Guardgress showcases a Web Application Firewall (WAF) integration within a Kubernetes Ingress Controller"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.authors="h3adex"

COPY --from=builder /app/main /bin/main
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
CMD ["/bin/main"]
