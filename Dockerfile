FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/faktorial-public-app .

FROM alpine:3.22

RUN adduser -D -H -u 10001 appuser
WORKDIR /app
USER appuser

COPY --from=build /out/faktorial-public-app /usr/local/bin/faktorial-public-app
COPY --from=build /src/static /app/static

ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/faktorial-public-app"]
