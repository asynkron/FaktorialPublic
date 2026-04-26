#!/usr/bin/env sh
set -eu

image="rogeralsing/faktorialpublic"
tag="${1:-latest}"
full_image="${image}:${tag}"
platform="${DOCKER_PLATFORM:-linux/amd64}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is not installed or not on PATH" >&2
  exit 1
fi

docker_check_log="$(mktemp)"
docker version >"${docker_check_log}" 2>&1 &
docker_check_pid="$!"
docker_ready=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if ! kill -0 "${docker_check_pid}" 2>/dev/null; then
    if wait "${docker_check_pid}"; then
      docker_ready=1
    fi
    break
  fi
  sleep 1
done

if [ "${docker_ready}" != "1" ]; then
  kill "${docker_check_pid}" 2>/dev/null || true
  wait "${docker_check_pid}" 2>/dev/null || true
  cat >&2 <<'EOF'
Docker is not responding.

Restart Docker Desktop, then verify it with:

  docker version
  docker ps

After that, run ./build.sh again.
EOF
  rm -f "${docker_check_log}"
  exit 1
fi
rm -f "${docker_check_log}"

echo "Building and pushing ${full_image} for ${platform}"
docker buildx build --platform "${platform}" --provenance=false --progress=plain -t "${full_image}" --push .

if [ "${tag}" != "latest" ]; then
  echo "Building and pushing ${image}:latest for ${platform}"
  docker buildx build --platform "${platform}" --provenance=false --progress=plain -t "${image}:latest" --push .
fi
