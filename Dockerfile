FROM golang:1.22-alpine AS build
ENV GOPROXY=https://proxy.golang.org,direct

WORKDIR /src
COPY go.mod go.sum ./
COPY . .
RUN go get github.com/tiktoken-go/tokenizer@v0.4.0
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/m365-native ./cmd/server
RUN cp go.sum /out/go.sum

FROM alpine:3.20
RUN addgroup -S m365 && adduser -S -G m365 m365 \
    && mkdir -p /data /app
WORKDIR /app
COPY --from=build /out/m365-native /app/m365-native
RUN chown -R m365:m365 /app /data
USER m365
EXPOSE 4141
ENV M365_LISTEN=0.0.0.0:4141 \
    M365_CONFIG=/data/accounts.json \
    M365_TOKEN_CACHE=/data/token-cache.json \
    M365_SESSION_CACHE=/data/sessions.json \
    M365_API_KEYS=/data/api-keys.json \
    M365_ADMIN_PASSWORD_FILE=/run/secrets/m365_admin_password
VOLUME ["/data"]
ENTRYPOINT ["/app/m365-native"]
