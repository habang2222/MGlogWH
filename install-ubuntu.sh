#!/usr/bin/env bash
set -euo pipefail
umask 077

# Build as an ordinary user first. This step only installs the already-built
# collector and its source into root-owned locations.
if (( EUID != 0 )); then
  echo "Run this installer with sudo after building MGlogWH." >&2
  exit 1
fi
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo "MGlogWH currently supports Linux x86_64 only." >&2
  exit 1
fi
/usr/bin/python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' || {
  echo "/usr/bin/python3 must be Python 3.12 or newer for the systemd service." >&2
  exit 1
}

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
build_dir=${MGLOGWH_BUILD_DIR:-$source_dir/build}
if [[ $build_dir != /* ]]; then
  build_dir=$source_dir/$build_dir
fi
for artifact in "$build_dir/collector" "$build_dir/sensor.bpf.o"; do
  if [[ ! -f $artifact || -L $artifact ]]; then
    echo "Missing build artifact: $artifact. Run make in the MGlogWH directory first." >&2
    exit 1
  fi
done
if [[ -d /run/systemd/system ]] && systemctl is-active --quiet mglogwh.service; then
  echo "Stop mglogwh.service before replacing its installed code." >&2
  exit 1
fi

for directory in /opt/mglogwh /opt/mglogwh/build /opt/mglogwh/licenses /opt/mglogwh/examples \
                 /etc/mglogwh /var/lib/mglogwh; do
  if [[ -L $directory ]]; then
    echo "Refusing symlinked install directory: $directory" >&2
    exit 1
  fi
  if [[ -e $directory && ( ! -d $directory || $(stat -c %u "$directory") != 0 ) ]]; then
    echo "Install directory must be a root-owned directory: $directory" >&2
    exit 1
  fi
  if [[ -d $directory ]]; then
    mode=$(stat -c %a "$directory")
    if (( (8#$mode & 0022) != 0 )); then
      echo "Install directory must not be group/world writable: $directory" >&2
      exit 1
    fi
  fi
done
source_files=(manage.py ledger.py collector.c sensor.bpf.c event.h tenant.h
              quarantine.h rules.h Makefile README.md RULES.md LEDGER.md QUARANTINE.md
              THIRD_PARTY.md)
for name in "${source_files[@]}"; do
  destination=/opt/mglogwh/$name
  if [[ ! -f $source_dir/$name || -L $source_dir/$name || -L $destination ||
        ( -e $destination &&
          ( ! -f $destination || $(stat -c %u "$destination") != 0 ) ) ]]; then
    echo "Missing or unsafe source/destination: $name" >&2
    exit 1
  fi
done
shopt -s nullglob
licenses=("$source_dir"/licenses/*)
if (( ${#licenses[@]} == 0 )); then
  echo "Missing third-party license files." >&2
  exit 1
fi
for license in "${licenses[@]}"; do
  if [[ ! -f $license || -L $license || -L /opt/mglogwh/licenses/${license##*/} ]]; then
    echo "Missing or symlinked license: ${license##*/}" >&2
    exit 1
  fi
done
for source in "$source_dir/config.json" "$source_dir/packaging/mglogwh.service" \
              "$source_dir/packaging/mglogwh.logrotate"; do
  if [[ ! -f $source || -L $source ]]; then
    echo "Missing or symlinked source: $source" >&2
    exit 1
  fi
done
examples=("$source_dir"/examples/*.json)
if (( ${#examples[@]} != 4 )); then
  echo "Expected four validated rule examples in examples/." >&2
  exit 1
fi
for example in "${examples[@]}"; do
  destination=/opt/mglogwh/examples/${example##*/}
  if [[ ! -f $example || -L $example || -L $destination ||
        ( -e $destination &&
          ( ! -f $destination || $(stat -c %u "$destination") != 0 ) ) ]]; then
    echo "Missing or unsafe rule example: ${example##*/}" >&2
    exit 1
  fi
done
for destination in /etc/mglogwh/config.json /etc/systemd/system/mglogwh.service \
                   /etc/logrotate.d/mglogwh /opt/mglogwh/build/collector \
                   /opt/mglogwh/build/sensor.bpf.o; do
  if [[ -L $destination || ( -e $destination &&
        ( ! -f $destination || $(stat -c %u "$destination") != 0 ) ) ]]; then
    echo "Installed file must be regular and root-owned: $destination" >&2
    exit 1
  fi
done

install -d -o root -g root -m 0755 /opt/mglogwh /opt/mglogwh/build /opt/mglogwh/licenses /opt/mglogwh/examples
install -d -o root -g root -m 0700 /etc/mglogwh /var/lib/mglogwh
# Also reject a manually started collector before replacing installed code.
exec {collector_lock_fd}>/var/lib/mglogwh/collector.lock
if ! flock -n "$collector_lock_fd"; then
  echo "Stop the running collector before replacing its installed code." >&2
  exit 1
fi

for name in "${source_files[@]}"; do
  install -o root -g root -m 0644 "$source_dir/$name" "/opt/mglogwh/$name"
done
for license in "${licenses[@]}"; do
  install -o root -g root -m 0644 "$license" /opt/mglogwh/licenses/
done
for example in "${examples[@]}"; do
  install -o root -g root -m 0644 "$example" /opt/mglogwh/examples/
done
install -o root -g root -m 0755 "$build_dir/collector" /opt/mglogwh/build/collector
install -o root -g root -m 0644 "$build_dir/sensor.bpf.o" /opt/mglogwh/build/sensor.bpf.o

if [[ ! -e /etc/mglogwh/config.json ]]; then
  install -o root -g root -m 0600 "$source_dir/config.json" /etc/mglogwh/config.json
else
  chmod 0600 /etc/mglogwh/config.json
fi

install -o root -g root -m 0644 "$source_dir/packaging/mglogwh.service" /etc/systemd/system/mglogwh.service
install -o root -g root -m 0644 "$source_dir/packaging/mglogwh.logrotate" /etc/logrotate.d/mglogwh
if [[ -d /run/systemd/system ]]; then
  systemctl daemon-reload
fi
echo "Installed MGlogWH in /opt/mglogwh with configuration in /etc/mglogwh/config.json."
echo "Review the configuration, then run: sudo systemctl enable --now mglogwh"
