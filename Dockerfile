FROM golang:1.21-alpine as builder
RUN apk --update add ca-certificates tzdata
WORKDIR /app
COPY . ./
RUN go get -v -t -d ./...
RUN go build cmd/server/main.go

FROM scratch
ENV TZ=Europe/Berlin
COPY --from=builder /app/main /bin/main
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
CMD ["/bin/main"]
