FROM golang:alpine3.7

RUN apk add --update git gcc libpcap-dev musl-dev && apk del --purge

RUN go get github.com/google/gopacket github.com/prometheus/client_golang/prometheus github.com/prometheus/client_golang/prometheus/promhttp github.com/google/gopacket/pcap github.com/google/gopacket/layers

WORKDIR /go/src

COPY . .

#RUN CGO_ENABLED=0 go build -a -installsuffix cgo -o /bin/network-exporter
RUN go build -o /bin/network-exporter


FROM alpine:3.7
RUN apk add --update libpcap && apk del --purge
COPY --from=0 /bin/network-exporter /bin/network-exporter

EXPOSE 9097

#RUN addgroup exporter &&\
#    adduser -S -G exporter exporter &&\
#    apk --update add ca-certificates &&\
#    rm -rf /var/cache/apk/*

USER root

ENTRYPOINT [ "/bin/network-exporter" ]

CMD [ "-i=eth0" ]
