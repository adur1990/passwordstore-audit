#!/usr/bin/env bash

set -Eeuo pipefail
trap cleanup SIGINT SIGTERM ERR EXIT

usage() {
  cat <<EOF
Usage: $(basename "${BASH_SOURCE[0]}") [-h] [-v] [-b] [-w] [-o] [-n]

Script description here.

Available options:

-h, --help      Print this help and exit
-v, --verbose   Print script debug info
-n, --no-color  Disable colored output (e.g., for scripting)
-b, --breached  Check if any password was breached using Have I Been Pwned API
                (Requires "pass audit" extension to be installed)
-w, --weak      Check if any password is weak using Dropbox' zxcvbn algorithm.
                (Requires "pass audit" extension to be installed)
-o, --old       Check if any password is too old.
                (Requires "pass ages" extension to be installed)
-d, --dup       Check if any password is used more than once.
EOF
  exit
}

cleanup() {
  trap - SIGINT SIGTERM ERR EXIT 
}

NOFORMAT=''
RED=''
GREEN=''
ORANGE=''

BREACH=false
WEAK=false
OLD=false
DUP=false

declare -a BREACHED_PWS=()
declare -a WEAK_PWS=()
declare -a OLD_PWS=()
declare -a DUP_PWS=()

setup_colors() {
  if [[ -t 2 ]] && [[ -z "${NO_COLOR-}" ]] && [[ "${TERM-}" != "dumb" ]]; then
    NOFORMAT='\033[0m' RED='\033[0;31m' GREEN='\033[0;32m' ORANGE='\033[0;33m'
  else
    NOFORMAT='' RED='' GREEN='' ORANGE=''
  fi
}

msg() {
  echo >&2 -e "${1-}"
}

die() {
  local msg=$1
  local code=${2-1} # default exit status 1
  msg "$msg"
  exit "$code"
}

parse_params() {
  while :; do
    case "${1-}" in
    -h | --help) usage ;;
    -v | --verbose) set -x ;;
    -n | --no-color) NO_COLOR=1 ;;
    -b | --breached) BREACH=true ;;
    -w | --weak) WEAK=true ;;
    -o | --old) OLD=true ;;
    -d | --dup) DUP=true ;;
    -?*) die "Unknown option: $1" ;;
    *) break ;;
    esac
    shift
  done

  return 0
}

check_breach_and_weak() {
  local audit_result
  local mode=$1

  if [[ "$mode" == 0 ]]; then
    msg "${GREEN}Checking whether any password is breached or weak.${NOFORMAT}"
  elif [[ "$mode" == 1 ]]; then
    msg "${GREEN}Checking whether any password is breached.${NOFORMAT}"
  elif [[ "$mode" == 2 ]]; then
    msg "${GREEN}Checking whether any password is weak.${NOFORMAT}"
  fi

  audit_result=$(pass audit 2> /dev/null)

  while IFS= read -r result; do
    if [[ "$result" =~ .*Password[[:space:]]breached:.* && ( $mode == 0 || $mode == 1 ) ]]; then
      res_str=$(echo "$result"| cut -c 15-)
      BREACHED_PWS+=( "$res_str" )
    fi

    if [[ "$result" =~ .*Weak[[:space:]]password[[:space:]]detected:.* && ( $mode == 0 || $mode == 2 ) ]]; then
      res_str=$(echo "$result"| cut -c 15-)
      WEAK_PWS+=( "$res_str" )
    fi
  done <<< "$audit_result"
}

check_breach() {
  check_breach_and_weak 1
}

check_weak() {
  check_breach_and_weak 2
}

check_old() {
  msg "${GREEN}Checking whether any password used for more than 2 months.${NOFORMAT}"
  cur_time=$(date +%s)
  all_ages=()
  while IFS='' read -r line; do
    #$(echo "$line" | cut -d$'\t' -f3)
    all_ages+=("$line");
  done < <(pass ages 2> /dev/null | sort)

  for age in "${all_ages[@]}"; do
    unix_ts=$(echo "$age" | cut -d$'\t' -f1)
    rel_time=$(echo "$age" | cut -d$'\t' -f2)
    pw_name=$(echo "$age" | cut -d$'\t' -f3)

    used_time=$(( "$cur_time" - "$unix_ts" ))

    if [[ used_time -ge 5270294 ]]; then
      res_str="Old password detected: $pw_name's password was set $rel_time"
      OLD_PWS+=( "$res_str" )
    fi
  done
}

find_duplicates() {
  msg "${GREEN}Checking whether any password is used mutliple times.${NOFORMAT}"
  local root_path=""

  if test -n "${PASSWORD_STORE_DIR-}"; then
    root_path="$PASSWORD_STORE_DIR"
  else
    root_path="$HOME/.password-store"
  fi

  declare -A all_passwords

  while IFS= read -r -d '' pw_file; do
    cur_pw="$(gpg -d "$pw_file" 2> /dev/null | head -1)"

    if [ -v 'all_passwords[$cur_pw]' ]; then
      pw_list=( "${all_passwords[$cur_pw]}" )
      pw_list+=( "$pw_file" )
      all_passwords["$cur_pw"]="${pw_list[*]}"
    else
      declare -a pw_list
      pw_list=( "$pw_file" )
      all_passwords["$cur_pw"]="${pw_list[*]}"
    fi
  done <   <(find "$root_path" -name "*.gpg" -print0)

  for pws in "${!all_passwords[@]}"; do
    pfiles_string=${all_passwords[$pws]}
    read -r -a pfiles <<< "$pfiles_string"
      
    if [ ${#pfiles[@]} -gt 1 ]; then
      base_msg="Password used multiple times: $pws"
      for pfile in "${pfiles[@]}"; do
        fname=${pfile#"$root_path/"}
        base_msg+="\n    -> $fname"
      done
      DUP_PWS+=("$base_msg")
    fi
  done
}

check_requirements() {
  local requirement_missing=false

  if [ ! "${BASH_VERSINFO:-0}" -ge 4 ]; then
    msg "${RED}Bash version 4 or greater is required.${NOFORMAT}"
    requirement_missing=true
  fi

  if ! pass audit --help > /dev/null 2>&1; then
    msg "${RED}Please install 'pass audit' extension to check for breached and weak passwords${NOFORMAT}"
    requirement_missing=true
  fi
  
  if ! pass ages --help > /dev/null 2>&1; then
    msg "${RED}Please install 'pass ages' extension to check for old passwords${NOFORMAT}"
    requirement_missing=true
  fi

  if [[ "$requirement_missing" == true ]]; then
    die "${RED}Please satisfy the missing requirements${NOFORMAT}" 1
  fi
}

report() {
  set +x

  if [[ "$BREACH" == true ]]; then
    if [[ "${#BREACHED_PWS[@]}" -gt 0 ]]; then
      msg "${RED}Found breached passwords${NOFORMAT}"
      for pws in "${BREACHED_PWS[@]}"; do
        msg "${ORANGE}  $pws${NOFORMAT}"
      done
    else
      msg "${GREEN}No breached passwords found${NOFORMAT}"
    fi
  fi

  if [[ "$WEAK" == true ]]; then
    if [[ "${#WEAK_PWS[@]}" -gt 0 ]]; then
      msg "${RED}Found weak passwords${NOFORMAT}"
      for pws in "${WEAK_PWS[@]}"; do
        msg "${ORANGE}  $pws${NOFORMAT}"
      done
    else
      msg "${GREEN}No weak passwords found${NOFORMAT}"
    fi
  fi

  if [[ "$OLD" == true ]]; then
    if [[ "${#OLD_PWS[@]}" -gt 0 ]]; then
      msg "${RED}Found old passwords${NOFORMAT}"
      for pws in "${OLD_PWS[@]}"; do
        msg "${ORANGE}  $pws${NOFORMAT}"
      done
    else
      msg "${GREEN}No old passwords found${NOFORMAT}"
    fi
  fi

  if [[ "$DUP" == true ]]; then
    if [[ "${#DUP_PWS[@]}" -gt 0 ]]; then
      msg "${RED}Found duplicate passwords${NOFORMAT}"
      for pws in "${DUP_PWS[@]}"; do
        msg "${ORANGE}  $pws${NOFORMAT}"
      done
    else
      msg "${GREEN}No duplicate passwords found${NOFORMAT}"
    fi
  fi
}

parse_params "$@"
setup_colors

check_requirements

msg "${GREEN}Starting password checks. The individual parts may take some time, please be patient.${NOFORMAT}"

if [[ "$BREACH" == true && "$WEAK" == true ]]; then
  check_breach_and_weak 0
elif [[ "$BREACH" == true ]]; then
  check_breach
elif [[ "$WEAK" == true ]]; then
  check_weak
fi

if [[ "$OLD" == true ]]; then
  check_old
fi

if [[ "$DUP" == true ]]; then
  find_duplicates
fi

report

die "${GREEN}Done.${NOFORMAT}" 0