#!/bin/bash
case "$1" in
	live)
		echo "Starting realtime capture"
		args=(--driver fx2lafw --config samplerate=1M --continuous)
		;;
	*)
		args=(--input-file "$1")
		;;
esac

export SIGROKDECODE_DIR=$(readlink -f $(dirname "${BASH_SOURCE[0]}")/..)
sigrok-cli \
	"${args[@]}" \
	-P uart:rx=D0:tx=D1,vesc:json=1 \
	-P uart:rx=D2:tx=D3,vesc:json=1 \
	-A vesc=tx_packet,vesc=rx_packet |
sed -urn 's#^vesc-([0-9]+): \{#{"id": \1,#p' |
jq --unbuffered .
