FROM docker.io/library/golang:alpine as builder

ENV GO111MODULE=on

WORKDIR /build

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o smtp-relay . \
    && apk --no-cache add ca-certificates \
    && update-ca-certificates

FROM scratch

COPY --from=builder /build/smtp-relay /smtp-relay
COPY --from=builder /build/config.example.json /config.json
COPY --from=builder /usr/local/share/ca-certificates /usr/local/share/ca-certificates
COPY --from=builder /etc/ssl /etc/ssl


EXPOSE 2525
EXPOSE 4650

CMD ["/smtp-relay"]