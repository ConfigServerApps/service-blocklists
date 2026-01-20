#!/bin/bash

# #
#   @for                https://github.com/ConfigServer-Software/service-blocklists
#   @workflow           blocklist-generate.yml
#   @type               bash script
#   @summary            utilizes various whois services and allows you to fetch a list of IP addresses associated with an ASN.
#   
#   @terminal           .github/scripts/bl-whois.sh \
#                           blocklists/privacy/privacy_facebook.ipset
#                           AS32934
#   
#                       .github/scripts/bl-whois.sh \
#                           blocklists/privacy/privacy_facebook.ipset
#                           AS32934 \
#                           whois.radb.net
#   
#                       .github/scripts/bl-whois.sh \
#                           blocklists/privacy/privacy_facebook.ipset
#                           AS32934 \
#                           whois.radb.net \
#                           '#|^;|^$'
#   
#   @workflow           # Privacy › Facebook
#                       chmod +x ".github/scripts/bl-whois.sh"
#                       run_facebook=".github/scripts/bl-whois.sh blocklists/privacy/privacy_facebook.ipset AS32934"
#                       eval "./$run_facebook"
#   
#   @command            bl-whois.sh
#                           <ARG_SAVEFILE>              required
#                           <ARG_ASN>                   required
#                           <ARG_WHOIS_SERVICE>         optional
#                           <ARG_GREP_FILTER>           optional
#   
#                       bl-whois.sh blocklists/privacy/privacy_facebook.ipset AS32934 whois.radb.net '#|^;|^$'
#   
#                       📁 .github
#                           📁 scripts
#                               📄 bl-whois.sh
#                           📁 workflows
#                               📄 blocklist-generate.yml
#   
# #

app_file_this=$(basename "$0")                                                      #  bl-geolite2_asn.sh   (with ext)
app_file_bin="${app_file_this%.*}"                                                  #  bl-geolite2_asn      (without ext)

# #
#   define > folders
# #

app_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"            #  path where script was last found in
app_dir_this_dir="${PWD}"                                                           #  current script directory
app_dir_github="${app_dir_this_dir}/.github"                                        #  .github folder

# #
#   Define › Colors
#   
#   Use the color table at:
#       - https://gist.github.com/fnky/458719343aabd01cfb17a3a4f7296797
# #

esc=$(printf '\033')
end="${esc}[0m"
bgEnd="${esc}[49m"
fgEnd="${esc}[39m"
bold="${esc}[1m"
dim="${esc}[2m"
underline="${esc}[4m"
blink="${esc}[5m"
white="${esc}[97m"
black="${esc}[0;30m"
redl="${esc}[0;91m"
redd="${esc}[38;5;196m"
magental="${esc}[38;5;197m"
magentad="${esc}[38;5;161m"
fuchsial="${esc}[38;5;206m"
fuchsiad="${esc}[38;5;199m"
bluel="${esc}[38;5;33m"
blued="${esc}[38;5;27m"
greenl="${esc}[38;5;47m"
greend="${esc}[38;5;35m"
orangel="${esc}[38;5;208m"
oranged="${esc}[38;5;202m"
yellowl="${esc}[38;5;226m"
yellowd="${esc}[38;5;214m"
greyl="${esc}[38;5;250m"
greym="${esc}[38;5;244m"
greyd="${esc}[38;5;240m"
navy="${esc}[38;5;62m"
olive="${esc}[38;5;144m"
peach="${esc}[38;5;204m"
cyan="${esc}[38;5;6m"
bgVerbose="${esc}[1;38;5;15;48;5;125m"
bgDebug="${esc}[1;38;5;15;48;5;237m"
bgInfo="${esc}[1;38;5;15;48;5;27m"
bgOk="${esc}[1;38;5;15;48;5;64m"
bgWarn="${esc}[1;38;5;16;48;5;214m"
bgDanger="${esc}[1;38;5;15;48;5;202m"
bgError="${esc}[1;38;5;15;48;5;160m"

# #
#   Define › App
# #

app_name="Whois Lookup"                                             # name of app
app_desc="Fetch list of IP addresses utilizing whois binary"        # desc
app_ver="1.2.0.0"                                                   # current script version
app_repo="configserver-software/service-blocklists"                 # repository
app_repo_branch="main"                                              # repository branch
app_agent="Mozilla/5.0 (Windows NT 10.0; WOW64) "\
"AppleWebKit/537.36 (KHTML, like Gecko) "\
"Chrome/51.0.2704.103 Safari/537.36"                                # user agent used with curl

# #
#   Define › Args
# #

argDryrun="false"                                                   # Enable dryrun
argASN=""                                                           # Process specific ASN
argDevMode="false"                                                  # dev mode
argFolder=""
argFile=""

# #
#   Define › Logging functions
#   
#   verbose "This is an verbose message"
#   debug "This is an debug message"
#   info "This is an info message"
#   ok "This is an ok message"
#   warn "This is a warn message"
#   danger "This is a danger message"
#   error "This is an error message"
# #

verbose( )
{
    case "${argVerbose:-0}" in
        1|true|TRUE|yes|YES)
            printf '\033[0m\r%-42s %-65s\n' "   ${bgVerbose} VRBO ${end}" "${greym} $1 ${end}"
            ;;
    esac
}

debug( )
{
    if [ "$argDevEnabled" = "true" ] || [ "$argDryrun" = "true" ]; then
        printf '\033[0m\r%-42s %-65s\n' "   ${bgDebug} DBUG ${end}" "${greym} $1 ${end}"
    fi
}

info( )
{
    printf '\033[0m\r%-41s %-65s\n' "   ${bgInfo} INFO ${end}" "${greym} $1 ${end}"
}

ok( )
{
    printf '\033[0m\r%-41s %-65s\n' "   ${bgOk} PASS ${end}" "${greym} $1 ${end}"
}

warn( )
{
    printf '\033[0m\r%-42s %-65s\n' "   ${bgWarn} WARN ${end}" "${greym} $1 ${end}"
}

danger( )
{
    printf '\033[0m\r%-42s %-65s\n' "   ${bgDanger} DNGR ${end}" "${greym} $1 ${end}"
}

error( )
{
    printf '\033[0m\r%-42s %-65s\n' "   ${bgError} FAIL ${end}" "${greym} $1 ${end}"
}

label( )
{
    printf '\033[0m\r%-31s %-65s\n' "   ${greyd}        ${end}" "${greyd} $1 ${end}"
}

print( )
{
    echo "${greym}$1${end}"
}

# #
#   truncate text; add ...
#   
#   @usage
#       truncate "This is a long string" 10 "..."
# #

truncate()
{
    text=$1
    maxlen=$2
    suffix=${3:-}

    len=$(printf %s "${text}" | wc -c | tr -d '[:space:]')

    if [ "${len}" -gt "${maxlen}" ]; then
        printf '%s%s\n' "$(printf %s "${text}" | cut -c1-"${maxlen}")" "${suffix}"
    else
        printf '%s\n' "${text}"
    fi
}

# #
#   Print › Demo Notifications
#   
#   Outputs a list of example notifications
#   
#   @usage          demoNoti
# #

demoNoti()
{
    verbose "This is an verbose message"
    debug "This is an debug message"
    info "This is an info message"
    ok "This is an ok message"
    warn "This is a warn message"
    danger "This is a danger message"
    error "This is an error message"
}

# #
#   Print › Line
#   
#   Prints single line horizontal line, no text
#   
#   @usage          prin0
# #

prin0()
{
    _p0_indent="  "
    _p0_box_width=110
    _p0_line_width=$(( _p0_box_width + 2 ))

    _p0_line=""
    i=1
    while [ "$i" -le "${_p0_line_width}" ]; do
        _p0_line="${_p0_line}─"
        i=$(( i + 1 ))
    done

    printf '\n'
    printf "%b%s%s%b\n" "${greyd}" "${_p0_indent}" "${_p0_line}" "${reset}"
    printf '\n'

    unset _p0_indent _p0_box_width _p0_line_width _p0_line i
}


# #
#   Print › Box › Single
#   
#   Prints single line with a box surrounding it.
#   
#   @usage          prinb "${APP_NAME_SHORT:-CSF} › Customize csf.config"
# #

prinb()
{
    _prinb_title="$*"
    _prinb_indent="   "                                                         # Left padding
    _prinb_padding=6                                                            # Extra horizontal space around text
    _prinb_title_length=${#_prinb_title}
    _prinb_inner_width=$(( _prinb_title_length + _prinb_padding ))
    _prinb_box_width=110

    # Minimum width for aesthetics
    if [ "$_prinb_inner_width" -lt "$_prinb_box_width" ]; then
        _prinb_inner_width=$_prinb_box_width
    fi

    # Horizontal border
    _prinb_line=""
    i=1
    while [ "$i" -le "$_prinb_inner_width" ]; do
        _prinb_line="${_prinb_line}─"
        i=$(( i + 1 ))
    done

    # Draw box
    printf '\n'
    printf '\n'
    printf "%b%s┌%s┐\n" "${greym}" "$_prinb_indent" "$_prinb_line"
    printf "%b%s│  %-${_prinb_inner_width}s \n" "${greym}" "$_prinb_indent" "$_prinb_title"
    printf "%b%s└%s┘%b\n" "${greym}" "$_prinb_indent" "$_prinb_line" "${reset}"
    printf '\n'

    unset _prinb_title _prinb_indent _prinb_padding \
          _prinb_title_length _prinb_inner_width _prinb_box_width \
          _prinb_line i
}

# #
#   Print › Box › Paragraph
#   
#   Places an ASCII box around text. Supports multi-lines with \n.
#   
#   Determines the character count if color codes are used and ensures that the box borders are aligned properly.
#   
#   If using emojis; adjust the spacing so that the far-right line will align with the rest. Add the number of spaces
#   to increase the value, which is represented with a number enclosed in square brackets.
#     [1]           add 1 space to the right.
#     [2]           add 2 spaces to the right.
#     [-1]          remove 1 space to the right (needed for some emojis depending on if the emoji is 1 or 2 bytes)
#   
#   @usage          prinp "Certificate Generation Successful" "Your new certificate and keys have been generated successfully.\n\nYou can find them in the ${greenl}${app_dir_output}${greyd} folder."
#                   prinp "🎗️[1]  ${file_domain_base}" "The following description will show on multiple lines with a ASCII box around it."
#                   prinp "📄[-1] File Overview" "The following list outlines the files that you have generated using this utility, and what certs/keys may be missing."
#                   prinp "➡️[15]  ${bluel}Paths${end}"
# #

prinp()
{
    local title="$1"
    shift
    local text="$*"

    local indent="  "
    local box_width=110
    local pad=1

    local content_width=$(( box_width ))
    local inner_width=$(( box_width - pad*2 ))

    print
    print

    local hline
    hline=$(printf '─%.0s' $(seq 1 "$content_width"))

    printf "${greyd}%s┌%s┐\n" "$indent" "$hline"

    # #
    #   Title
    #   
    #   Extract optional [N] adjustment from title (signed integer), portably
    # #

    local emoji_adjust=0
    local display_title="$title"

    # #
    #   Get content inside first [...] (if present)
    # #

    if printf '%s\n' "$title" | grep -q '\[[[:space:]]*[-0-9][-0-9[:space:]]*\]'; then

        # #
        #   Extract numeric inside brackets (allow optional leading -)
        #   - use sed to capture first bracketed token, then strip non-digit except leading -
        # #

        local bracket
        bracket=$(printf '%s' "$title" | sed -n 's/.*\[\([-0-9][-0-9]*\)\].*/\1/p')

        # #
        #   Validate numeric and assign, otherwise fallback to 0
        # #
    
        if printf '%s\n' "$bracket" | grep -qE '^-?[0-9]+$'; then
            emoji_adjust=$bracket
        else
            emoji_adjust=0
        fi

        # #
        #   Remove the first [...] token from the display_title
        # #
    
        display_title=$(printf '%s' "$title" | sed 's/\[[^]]*\]//')
    fi

    # #
    #   Sanity: ensure emoji_adjust is a decimal integer so math works
    # #

    case "$emoji_adjust" in
        ''|*[!0-9-]*)
            emoji_adjust=0
            ;;
    esac

    local title_width=$(( content_width - pad ))

    # #
    #   Account for emoji adjustment in visible length calculation
    # #
  
    local title_vis_len=$(( ${#display_title} - emoji_adjust ))
    printf "${greyd}%s│%*s${bluel}%s${greyd}%*s│\n" \
        "$indent" "$pad" "" "$display_title" "$(( title_width - title_vis_len ))" ""

    # #
    #   Only render body text if provided
    # #

    if [ -n "$text" ]; then
        printf "${greyd}%s│%-${content_width}s│\n" "$indent" ""

        # #
        #   Convert literal \n to real newlines
        # #

        text=$(printf "%b" "$text")

        # #
        #   Handle each line with ANSI-aware wrapping and true padding
        # #

        printf "%s" "$text" | while IFS= read -r line || [ -n "$line" ]; do

        # #
        #   Blank line
        # #
    
        if [ -z "$line" ]; then
            printf "${greyd}%s│%-*s│\n" "$indent" "$content_width" ""
            continue
        fi

        local out="" word
        for word in $line; do
            # #
            #   Strip ANSI for visible width
            # #
        
            local vis_out vis_len vis_word
            vis_out=$(printf "%s" "$out" | sed 's/\x1B\[[0-9;]*[A-Za-z]//g')
            vis_word=$(printf "%s" "$word" | sed 's/\x1B\[[0-9;]*[A-Za-z]//g')
            vis_len=$(( ${#vis_out} + ( ${#vis_out} > 0 ? 1 : 0 ) + ${#vis_word} ))

            if [ -z "$out" ]; then
                out="$word"
            elif [ $vis_len -le $inner_width ]; then
                out="$out $word"
            else
                # #
                #   Print and pad manually based on visible length
                # #

                local vis_len_full
                vis_len_full=$(printf "%s" "$out" | sed 's/\x1B\[[0-9;]*[A-Za-z]//g' | wc -c | tr -d ' ')
                local pad_spaces=$(( inner_width - vis_len_full ))
                [ $pad_spaces -lt 0 ] && pad_spaces=0
                printf "${greyd}%s│%*s%s%*s│\n" "$indent" "$pad" "" "$out" "$(( pad + pad_spaces ))" ""
                out="$word"
            fi
        done

        # #
        #   Final flush line
        # #
    
        if [ -n "$out" ]; then
            local vis_len_full pad_spaces
            vis_len_full=$(printf "%s" "$out" | sed 's/\x1B\[[0-9;]*[A-Za-z]//g' | wc -c | tr -d ' ')
            pad_spaces=$(( inner_width - vis_len_full ))
            [ $pad_spaces -lt 0 ] && pad_spaces=0
            printf "${greyd}%s│%*s%s%*s│\n" "$indent" "$pad" "" "$out" "$(( pad + pad_spaces ))" ""
        fi

        done
    fi

    printf "${greyd}%s└%s┘${reset}\n" "$indent" "$hline"
    print
}

# #
#   Define › Logging › Verbose
# #

log()
{
    case "${argVerbose:-0}" in
        1|true|TRUE|yes|YES)
            verbose "$@"
            ;;
    esac
}

# #
#   Check Sudo
# #

check_sudo( )
{
    if [ "$(id -u)" != "0" ]; then
        error "    ❌ Must run script with ${redl}sudo"
        exit 1
    fi
}

# #
#   Run Command
#   
#   Added when dryrun mode was added to the install.sh.
#   Allows for a critical command to be skipped if in --dryrun mode.
#       Throws a debug message instead of executing.
#   
#   argDryrun comes from global export in csf/install.sh
#   
#   @usage          run /sbin/chkconfig csf off
#                   run echo "ConfigServer"
#                   run chmod -v 700 "./${CSF_AUTO_GENERIC}"
# #

run()
{
    if [ "${argDryrun}" = "true" ]; then
        debug "    Drymode (skip): $*"
    else
        debug "    Run: $*"
        "$@"
    fi
}

# #
#   Set PATH
# #

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# #
#   Set Binaries
# #

WHOIS_BIN=$(which whois || echo "/usr/bin/whois")

# #
#   Sort Results
#   
#   @usage          line=$(parse_spf_record "${ip}" | sort_results)
# #

sort_results()
{
	declare -a ipv4 ipv6

	while read -r line ; do
		if [[ ${line} =~ : ]] ; then
			ipv6+=("${line}")
		else
			ipv4+=("${line}")
		fi
	done

	[[ -v ipv4[@] ]] && printf '%s\n' "${ipv4[@]}" | sort -g -t. -k1,1 -k 2,2 -k 3,3 -k 4,4 | uniq
	[[ -v ipv6[@] ]] && printf '%s\n' "${ipv6[@]}" | sort -g -t: -k1,1 -k 2,2 -k 3,3 -k 4,4 -k 5,5 -k 6,6 -k 7,7 -k 8,8 | uniq
}

# #
#   Arguments
#   
#   We are attempting to add dynamic arguments, meaning they can be in any order. this is because some of the arguments are
#   optional, and we support providing multiple ASN.
#   
#       ARG_SAVEFILE        (str)       always the first arg
#       ARG_WHOIS_SERVICE   (str)       specifies what whois service to use
#                                           - if string arg is valid URL (checked by regex)
#                                           - if string arg STARTS with `whois`
#       ARG_GREP_FILTER     (str)       specifies what grep pattern to use for filtering out results
#                                           - if string arg STARTS with ^
#                                           - if string arg STARTS with (
#                                           - if string arg ENDS with $
#                                           - if string arg ENDS with )
#       ARG_ASN             (str)       ASN to grab IP addresses from. supports multiple ASN numbers.
#                                           - if string arg STARTS with `AS`
# #

# #
#   Define Regex URL
# #

REGEX_URL='^(https?|ftp|file)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]\.[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]$'

for arg in "${@:1}"; do
    if [[ $arg == whois* ]] || [[ $arg =~ $REGEX_URL ]]; then
        ARG_WHOIS_SERVICE=${arg}
    fi
    if [[ $arg == ^* ]] || [[ $arg == \(* ]] || [[ $arg == *$ ]] || [[ $arg == *\) ]]; then
        ARG_GREP_FILTER=${arg}
    fi
done

# #
#   Defaults
# #

ARG_WHOIS_SERVICE="${ARG_WHOIS_SERVICE:-whois.radb.net}"
ARG_GREP_FILTER="${ARG_GREP_FILTER:-^#|^;|^$}"
ARG_SAVEFILE=$1

# #
#   Arguments > Validate
# #

if [ -z "$ARG_SAVEFILE" ]; then
    echo
    echo "  ⭕ ${yellowd}[${app_file_this}]${end}: No target file specified"
    echo
    exit 0
fi

if [ "$#" -lt 2 ]; then
    echo
    echo "  ⭕ ${yellowd}[${app_file_this}]${end}: Invalid ASN list specified for ${yellowd}${ARG_SAVEFILE}${end}"
    echo
    exit 0
fi

# #
#   No whois service specified, set to default
#       
# #

: "${ARG_WHOIS_SERVICE:=whois.radb.net}"

# #
#   Grep search pattern not provided, ignore comments and blank lines.
#   this is already done in the step before this grep exclude pattern is ran, but
#   we need a default grep pattern if one is not provided.
# #

: "${ARG_GREP_FILTER:=^#|^;|^$}"

# #
#   Define > app
# #

START_TIME=$(date +%s)
SECONDS=0                                                           # set seconds count for beginning of script
APP_FILE_PERM="${ARG_SAVEFILE}"                                     # perm file when building ipset list
total_lines=0                                                       # number of lines in doc
total_subnets=0                                                     # number of IPs in all subnets combined
total_ips=0                                                         # number of single IPs (counts each line)
templ_now=$(date -u)                                                # get current date in utc format
templ_id=$(basename -- ${APP_FILE_PERM})                            # ipset id, get base filename
templ_id="${templ_id//[^[:alnum:]]/_}"                              # ipset id, only allow alphanum and underscore, /description/* and /category/* files must match this value
templ_uuid=$(uuidgen -m -N "${templ_id}" -n @url)                   # uuid associated to each release
templ_desc=$(curl -sSL -A "${app_agent}" "https://raw.githubusercontent.com/${app_repo}/${app_repo_branch}/.github/descriptions/${templ_id}.txt")
templ_category=$(curl -sSL -A "${app_agent}" "https://raw.githubusercontent.com/${app_repo}/${app_repo_branch}/.github/categories/${templ_id}.txt")
templ_exp=$(curl -sSL -A "${app_agent}" "https://raw.githubusercontent.com/${app_repo}/${app_repo_branch}/.github/expires/${templ_id}.txt")
templ_url_service=$(curl -sSL -A "${app_agent}" "https://raw.githubusercontent.com/${app_repo}/${app_repo_branch}/.github/url-source/${templ_id}.txt")
regex_rule_isnum='^[0-9]+$'

# #
#   Default Values
# #

case $templ_desc in
    *"404: Not Found"*) templ_desc="#   No description provided" ;;
esac

case $templ_category in
    *"404: Not Found"*) templ_category="Uncategorized" ;;
esac

case $templ_exp in
    *"404: Not Found"*) templ_exp="6 hours" ;;
esac

case $templ_url_service in
    *"404: Not Found"*) templ_url_service="None" ;;
esac

# #
#   Output > Header
# #

prinp "${APP_NAME_SHORT:-CSF} > ${APP_FILE_PERM}" \
       "Generating blocklist using whois service. \
${greyd}\n\n${greym}id: 	    ${greyd}................${yellowl} ${templ_id}${greyd} \
${greyd}\n${greym}uuid:	        ${greyd}..............${yellowl} ${templ_uuid}${greyd} \
${greyd}\n${greym}category:  	${greyd}..........${yellowl} ${templ_category}${greyd} \
${greyd}\n${greym}action: 	    ${greyd}............${yellowl} ${app_file_this}${greyd}"

# #
#   output
# #

echo 
echo "  ⭐ Starting script ${greend}${app_file_this}${end}"

# #
#   Create or Clean file
# #

if [ -f $APP_FILE_PERM ]; then
    echo "  📄 Clean ${bluel}${APP_FILE_PERM}${end}"
    echo 
   > ${APP_FILE_PERM}
else
    echo "  📁 Create ${bluel}${APP_FILE_PERM}${end}"
    echo 
    mkdir -p $(dirname "${APP_FILE_PERM}")
    touch ${APP_FILE_PERM}
fi

# #
#   Func > Download List
#   
#   Downloads list of IPs and Subnets dependent on what ASN is provided.
#   
#   @arg        { asn_numbers, ... }
#   @arg        fileTemp
# #

download_list()
{

    local fnASN=$1
    local fnFile=$2
    local fnFileTemp="${2}.tmp"
    local dl_total_ips=0
    local dl_total_subnets=0

    echo "  🌎 Downloading ASN ${yellowd}${fnASN}${end} list to ${oranged}${fnFileTemp}${end}"

    whois_err=$(mktemp)

    # #
    #   Get raw WHOIS output into a variable
    # #

    raw_list=$(whois -h "${ARG_WHOIS_SERVICE}" -- "-i origin ${fnASN}" 2> "${whois_err}" \
        | grep ^route \
        | awk '{gsub("(route:|route6:)",""); print}' \
        | awk '{gsub(/ /,""); print}' \
        | grep -vi "^#|^;|^$" \
        | grep -vi "$ARG_GREP_FILTER" \
        | awk '{if (++dup[$0] == 1) print $0;}')

    if [ $? -ne 0 ] || [ -z "${raw_list}" ]; then
        echo "❌ WHOIS failed for ${fnASN}"
        echo "---- whois error ----"
        cat "$whois_err"
        echo "---------------------"
        rm -f "$whois_err"
    
        return 1
    fi

    rm -f "$whois_err"

    # #
    #   Sort using the existing function in the main shell
    # #

    printf "%s\n" "$raw_list" | sort_results > "$fnFileTemp"

    # #
    #   Calculate total num of IPs and subnets from ASN temp file
    # #

    echo "  📊 Fetching statistics for clean file ${oranged}${fnFileTemp}${end}"

    while IFS= read -r line || [ -n "$line" ]; do
        [[ -z "$line" ]] && continue
        case "$line" in \#*|\;*) continue ;; esac

        if [[ "$line" =~ : ]]; then
            dl_total_subnets=$((dl_total_subnets + 1))
            dl_total_ips=$((dl_total_ips + 1))
        elif [[ "$line" =~ / ]]; then
            dl_total_subnets=$((dl_total_subnets + 1))
            prefix=${line##*/}
            if [[ "$prefix" =~ ^[0-9]+$ ]] && [ "$prefix" -ge 0 ] && [ "$prefix" -le 32 ]; then
                ips=$((1 << (32 - prefix)))
            else
                ips=1
            fi
            dl_total_ips=$((dl_total_ips + ips))
        else
            dl_total_subnets=$((dl_total_subnets + 1))
            dl_total_ips=$((dl_total_ips + 1))
        fi
    done < "$fnFileTemp"

    # #
    #   Move temp file to final
    # #

    echo "  🚛 Move ${oranged}${fnFileTemp}${end} to ${bluel}${fnFile}${end}"
    cat "$fnFileTemp" >> "$fnFile"
    rm "$fnFileTemp"

    # #
    #   Print correct per-ASN stats now
    # #

    echo "  ➕ Added ${fuchsial}${dl_total_ips} IPs${end} and ${fuchsial}${dl_total_subnets} subnets${end} to ${bluel}${fnFile}${end}"
}

# #
#   Count ASN
#   
#   To make sure we add the correct amount of commas to the ASN list, as well as break up the ASN numbers per line
#   we need to get the total count available.
# #

asn_total=0                             # start at one, since the last step is base continent file
asn_step=0                              # count current asn in step
templ_asns=""                           # ASN list

for arg in "${@:2}"; do
    if [[ $arg == AS* ]]; then
        asn_total=$(( asn_total + 1 ))
    fi
done

# Hacky, remove one from total since step starts at 0
asn_total=$(( $asn_total - 1 ))

# #
#   Print list of ASN in template header.
#   Shows the first 5, and then the 6th is on a new line.
# #

for arg in "${@:2}"; do
    if [[ $arg == AS* ]]; then
        download_list "$arg" "$APP_FILE_PERM"
        echo

        if [ $((asn_step % 5)) -eq 0 ] && [ $asn_step -ne 0 ]; then
            # Start a new line after every 5 ASNs
            templ_asns+=$'\n#                   '"$arg"
        else
            # Append with comma
            if [ $asn_step -eq 0 ]; then
                templ_asns+="$arg"
            else
                templ_asns+=", $arg"
            fi
        fi

        asn_step=$((asn_step + 1))
    fi
done

# #
#   Sort
#       - sort lines numerically and create .sort file
#       - move re-sorted text from .sort over to real file
#       - remove .sort temp file
# #

sorting=$(cat "${APP_FILE_PERM}" | grep -vi "^#|^;|^$" | awk '{if (++dup[$0] == 1) print $0;}' | sort_results > ${APP_FILE_PERM}.sort)
> ${APP_FILE_PERM}
cat ${APP_FILE_PERM}.sort >> ${APP_FILE_PERM}
rm ${APP_FILE_PERM}.sort

# #
#   Format Counts
# #

# Recalculate totals AFTER all temp files are merged
total_ips=0
total_subnets=0

while IFS= read -r line || [ -n "$line" ]; do
    [[ -z "$line" ]] && continue
    case "$line" in \#*|\;*) continue ;; esac

    if [[ "$line" =~ : ]]; then
        total_subnets=$((total_subnets + 1))
        total_ips=$((total_ips + 1))
    elif [[ "$line" =~ / ]]; then
        total_subnets=$((total_subnets + 1))
        prefix=${line##*/}
        if [[ "$prefix" =~ ^[0-9]+$ ]] && [ "$prefix" -ge 0 ] && [ "$prefix" -le 32 ]; then
            ips=$((1 << (32 - prefix)))
        else
            ips=1
        fi
        total_ips=$((total_ips + ips))
    else
        total_subnets=$((total_subnets + 1))
        total_ips=$((total_ips + 1))
    fi
done < "$APP_FILE_PERM"

# #
#   Add commas to thousands
# #

total_lines=$(wc -l < "$APP_FILE_PERM")
total_lines=$(printf "%'d" "$total_lines")
total_ips=$(printf "%'d" "$total_ips")
total_subnets=$(printf "%'d" "$total_subnets")

# #
#   ed placement:
#   
#       0a  top of file
# #

ed -s ${APP_FILE_PERM} <<END_ED
0a
# #
#   🧱 Firewall Blocklist - ${APP_FILE_PERM}
#
#   @repo           https://raw.githubusercontent.com/${app_repo}/${app_repo_branch}/${APP_FILE_PERM}
#   @service        ${templ_url_service}
#   @id             ${templ_id}
#   @uuid           ${templ_uuid}
#   @updated        ${templ_now}
#   @entries        ${total_ips} ips
#                   ${total_subnets} subnets
#                   ${total_lines} lines
#   @asn            ${templ_asns}
#   @expires        ${templ_exp}
#   @category       ${templ_category}
#
${templ_desc}
# #

.
w
q
END_ED

# #
#   Finished
# #

# Capture end time
END_TIME=$(date +%s)

# Compute elapsed seconds
T=$(( END_TIME - START_TIME ))

# Calculate days, hours, minutes, seconds
D=$(( T / 86400 ))
H=$(( (T % 86400) / 3600 ))
M=$(( (T % 3600) / 60 ))
S=$(( T % 60 ))

echo "  🎌 ${greym}Finished! ${yellowd}${D} days ${H} hrs ${M} mins ${S} secs${end}"

# #
#   Output
# #

prinp "${APP_NAME_SHORT:-CSF} > ${APP_FILE_PERM}" \
       "Blocklist has finished generating successfully \
${greyd}\n\n${greym}ips: 	    ${greyd}...............${yellowl} ${total_ips}${greyd} \
${greyd}\n${greym}subnets:	        ${greyd}...........${yellowl} ${total_subnets}${greyd}"
