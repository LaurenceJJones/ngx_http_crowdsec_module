# HTTP helpers executed from the curl client container.

client_http_code() {
  local method="${1:-GET}"
  local url="${2:-http://nginx:8080/}"
  local data="${3:-}"
  local header="${4:-}"
  local -a args=(-s -o /dev/null -w '%{http_code}')

  if [[ -n "$header" ]]; then
    args+=(-H "$header")
  fi
  if [[ "$method" != "GET" ]]; then
    args+=(-X "$method")
  fi
  if [[ -n "$data" ]]; then
    args+=(-d "$data")
  fi

  docker exec "$CLIENT_CONTAINER" curl "${args[@]}" "$url"
}

client_curl_si() {
  local -a args=(-si)
  if (($# > 0)); then
    args+=("$@")
  else
    args+=(http://nginx:8080/)
  fi
  docker exec "$CLIENT_CONTAINER" curl "${args[@]}"
}

wait_for_http_code() {
  local expected="$1"
  local method="${2:-GET}"
  local url="${3:-http://nginx:8080/}"
  local data="${4:-}"
  local max="${5:-20}"
  local header="${6:-}"
  local code=""

  for _ in $(seq 1 "$max"); do
    code="$(client_http_code "$method" "$url" "$data" "$header")"
    if [[ "$code" == "$expected" ]]; then
      printf '%s' "$code"
      return 0
    fi
    sleep 1
  done

  echo "timeout waiting for HTTP ${expected}, last=${code}" >&2
  return 1
}

wait_for_http_not() {
  local not_expected="$1"
  local method="${2:-GET}"
  local url="${3:-http://nginx:8080/}"
  local data="${4:-}"
  local max="${5:-20}"
  local code=""

  for _ in $(seq 1 "$max"); do
    code="$(client_http_code "$method" "$url" "$data")"
    if [[ "$code" != "$not_expected" ]]; then
      printf '%s' "$code"
      return 0
    fi
    sleep 1
  done

  echo "timeout waiting for HTTP != ${not_expected}, last=${code}" >&2
  return 1
}

assert_http_code() {
  local expected="$1"
  shift
  run client_http_code "$@"
  assert_success
  assert_output "$expected"
}

assert_http_not() {
  local not_expected="$1"
  shift
  run client_http_code "$@"
  assert_success
  refute_output "$not_expected"
}

assert_http_eventually() {
  local expected="$1"
  local method="${2:-GET}"
  local url="${3:-http://nginx:8080/}"
  local data="${4:-}"
  local max="${STREAM_SYNC_WAIT:-20}"
  run wait_for_http_code "$expected" "$method" "$url" "$data" "$max"
  assert_success
  assert_output "$expected"
}

client_curl_body() {
  local method="${1:-GET}"
  local url="${2:-http://nginx:8080/}"
  local data="${3:-}"
  local -a args=(-s)

  if [[ "$method" != "GET" ]]; then
    args+=(-X "$method")
  fi
  if [[ -n "$data" ]]; then
    args+=(-d "$data")
  fi

  docker exec "$CLIENT_CONTAINER" curl "${args[@]}" "$url"
}

wait_for_response_contains() {
  local needle="$1"
  local method="${2:-GET}"
  local url="${3:-http://nginx:8080/}"
  local data="${4:-}"
  local max="${5:-${STREAM_SYNC_WAIT:-25}}"
  local body=""

  for _ in $(seq 1 "$max"); do
    body="$(client_curl_body "$method" "$url" "$data")"
    if [[ "$body" == *"$needle"* ]]; then
      printf '%s' "$body"
      return 0
    fi
    sleep 1
  done

  echo "timeout waiting for response containing '${needle}'" >&2
  echo "last body: ${body:0:500}" >&2
  return 1
}

assert_response_eventually_contains() {
  local needle="$1"
  shift
  run wait_for_response_contains "$needle" "$@"
  assert_success
}

wait_for_response_not_contains() {
  local needle="$1"
  local method="${2:-GET}"
  local url="${3:-http://nginx:8080/}"
  local data="${4:-}"
  local max="${5:-${STREAM_SYNC_WAIT:-25}}"
  local body=""

  for _ in $(seq 1 "$max"); do
    body="$(client_curl_body "$method" "$url" "$data")"
    if [[ "$body" != *"$needle"* ]]; then
      printf '%s' "$body"
      return 0
    fi
    sleep 1
  done

  echo "timeout waiting for response without '${needle}'" >&2
  return 1
}
