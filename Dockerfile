FROM golang:1.26.5

ENV OTEL_EXPORTER_OTLP_ENDPOINT=${OTEL_EXPORTER_OTLP_ENDPOINT:-http://localhost:4317}
ENV MIB_MODULES=${MIB_MODULES:-}


WORKDIR /app

COPY . .

RUN go build -o snmpotel -v ./...

EXPOSE 161
CMD ["./snmpotel"]