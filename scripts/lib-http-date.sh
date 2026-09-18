# Sourced by check-cidr.sh and verify-cidr-freshness.sh -- shared HTTP-date
# handling so there's one place to fix if the GNU/BSD `date` split below
# ever needs it, not two copies that could drift.

epoch_of_http_date() {
  local http_date="$1"
  if date --version >/dev/null 2>&1; then
    date -d "$http_date" +%s # GNU date
  else
    date -j -f "%a, %d %b %Y %H:%M:%S %Z" "$http_date" +%s # BSD date
  fi
}

days_since_http_date_file() {
  local timestamp_file="$1"
  local then now
  then=$(epoch_of_http_date "$(cat "$timestamp_file")")
  now=$(date +%s)
  echo $(( (now - then) / 86400 ))
}
