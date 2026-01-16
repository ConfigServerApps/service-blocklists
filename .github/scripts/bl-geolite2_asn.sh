#!/bin/bash

# #
#   @for                https://github.com/Aetherinox/csf-firewall
#   @workflow           blocklist-generate.yml
#   @type               bash script
#   @summary            Aetherx Blocklists > GeoLite2 ASN IPsets
#                       generates a set of IPSET files by reading the GeoLite2 csv file and splitting the IPs up into their associated ASN.
#                           blocklists/asn/geolite2/3000/asn_3598_microsoft_corp_as.ipset
#                           blocklists/asn/geolite2/5000/asn_5761_microsoft_corp_msn_as_saturn.ipset
#                           [...]
#   
#   @command            ./.github/scripts/bl-geolite2_asn.sh --license <LICENSE_KEY>                Download MaxMind DB from website and process
#                       ./.github/scripts/bl-geolite2_asn.sh --local --asn 7,10                     Only processes IPs with ASN 7 and 10
#                       ./.github/scripts/bl-geolite2_asn.sh --local --limit 1000                   Limits to first 1000 entries
#                       ./.github/scripts/bl-geolite2_asn.sh --local                                Use local copy of MM database in .github/local folder
#                       ./.github/scripts/bl-geolite2_asn.sh --local --dev                          Use local copy of MM database but doesn't run final steps
#                       ./.github/scripts/bl-geolite2_asn.sh --dry
#   
#                       ./.github/scripts/bl-geolite2_asn.sh --license <LICENSE_KEY> --folder C --file Cloudflare       custom folder and filename
# #

# #
#   📗 Usage
#   
#   This script downloads or uses a local copy of MaxMind's GeoLite2 Databases and extracts the data.
#       - CSV URL: https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key=LICENSE_KEY&suffix=zip
#       - MD5 URL: https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key=LICENSE_KEY&suffix=zip.md5
#   
#   The script requires a LICENSE KEY to Maxmind in order to obtain these databases. You can generate one at:
#       https://maxmind.com
#   Make sure to keep your license key secure, especially if running on GitHub Actions.
#   
#   The license key can be specified to download the latest MaxMind Database one of two ways:
#       1.  Use the argument --license when you run the script command
#       2.  Create a new file called `.github/aetherx.conf` with the contents:
#               LICENSE_KEY=YOUR_LICENSE_KEY
#   
#   Once you have a LICENSE KEY, you have two ways to use the MaxMind database
#       1.  Script will download the most recent databases when this script is ran, OR;
#       2.  Provide your own copies of the csv, or the zip + md5 file which contains the csv; pick ONE of the two:
#           1.  Using CSVs:
#               .github/local/GeoLite2-ASN-Blocks-IPv4.csv
#               .github/local/GeoLite2-ASN-Blocks-IPv6.csv
#           1.  Using ZIPs:
#               .github/local/GeoLite2-ASN-CSV.zip
#               .github/local/GeoLite2-ASN-CSV.zip.md5
#   
#   If not providing local db; download new copies of the MaxMind DBs by running the command:
#       ./.github/scripts/bl-geolite2_asn.sh --license YOUR_MAXMIND_LICENSE_KEY
#   
#   If using the local files, run the command
#       ./.github/scripts/bl-geolite2_asn.sh --local
#   
#   The DB will be opened, and each ASN will be grouped into subfolders. An ASN of 7 would be placed in the folder `/0/`:
#       ./blocklists/asn/geolite/ipv4/0/asn_7_the_defence_science_and_technology_laboratory.tmp
#       ./blocklists/asn/geolite/ipv6/0/asn_7_the_defence_science_and_technology_laboratory.tmp
#   
#   Once it finishes generating all the .tmp files for each ipv4 and ipv6, it will move them out of the ipv4 and ipv6
#   subfolder and bring them two sub-folders back, with the filename .ipset
#       ./blocklists/asn/geolite/asn_7_the_defence_science_and_technology_laboratory.ipset
# #

# #
#   📗 Custom Paths
#   
#   You can force ipsets to be stored in a specific folder and file by passing the args:
#       --folder c --file cloudflare
#   
#       Places all IPSETs in the path:
#           ./blocklists/asn/geolite/c/cloudflare.ipset
#   
#   Store all ASNs to a single file (database download):
#       ./.github/scripts/bl-geolite2_asn.sh --license <LICENSE_KEY> --folder c --file cloudflare --asn 13335,209242,202623,132892,395747,14789,203898
#   
#   Store all ASNs to a single file (local):
#       ./.github/scripts/bl-geolite2_asn.sh --local --folder c --file cloudflare --asn 13335,209242,202623,132892,395747,14789,203898
#       ./.github/scripts/bl-geolite2_asn.sh --local --folder c --file cloudflare --asn AS13335 AS209242 AS202623 AS132892 AS395747 AS14789 AS203898
# #

# #
#   😡 Aggressive Mode
#   
#   Aggressive mode will put all specified ASNs in two files instead of one.
#       1. The specified file/folder OR ASN folder
#       2. In a @general/aggressive.ipset
#   
#   Running the command:
#       ./.github/scripts/bl-geolite2_asn.sh --local --aggressive --folder C --file cloudflare --asn 13335,209242,202623,132892,395747,14789,203898 --debug
#   Will use the local database files:
#       .github/local/GeoLite2-ASN-CSV.zip
#       .github/local/GeoLite2-ASN-CSV.zip.md5
#   Will create the following blocklists:
#       1. blocklists/asn/geolite2/C/cloudflare.ipset
#       2. blocklists/asn/geolite2/@general/aggressive.ipset
#   Containing IPs for all ASNs listed
#       13335,209242,202623,132892,395747,14789,203898
# #

# #
#   📗 Local Mode
#   
#   Instead of downloading the MaxMind database, you can provide your own local copy.
#       Place your own copies of the csv, or the zip + md5 file which contains the csv; pick ONE of the two:
#           1.  Using CSVs:
#               .github/local/GeoLite2-ASN-Blocks-IPv4.csv
#               .github/local/GeoLite2-ASN-Blocks-IPv6.csv
#           1.  Using ZIPs:
#               .github/local/GeoLite2-ASN-CSV.zip
#               .github/local/GeoLite2-ASN-CSV.zip.md5
#   
#   To specify that you want to run the script in local mode, use the arguments:
#       .github/scripts/bl-geolite2_asn.sh -o
#       .github/scripts/bl-geolite2_asn.sh --local
# #

# #
#   📗 Test Script
#   
#   You can tell the script to only process a certain number of entries, instead of the entire database which takes a long time.
#       Option 1        Generate test csv, first 1000 entries
#                           tail -n +2 "${TEMPDIR}/${file_source_ipv4_csv}" | head -n 1000 > "${TEMPDIR}/GeoLite2-ASN-Blocks-IPv4.csv"
#                           tail -n +2 "${TEMPDIR}/${file_source_ipv6_csv}" | head -n 1000 > "${TEMPDIR}/GeoLite2-ASN-Blocks-IPv6.csv"
#   
#                       Move files to `local` folder
#   
#       Option 2        Use the argument `--limit, -l`
#                            ./.github/scripts/bl-geolite2_asn.sh --local -a 7,10
#   
#                       The command above will ONLY process any database entry with the ASN 7 and 10
# #

# #
#   📗 Dryrun Mode
#   
#   Simulates downloading and processing without actually performing the CURL requests.
#       .github/scripts/bl-geolite2_asn.sh -d
#       .github/scripts/bl-geolite2_asn.sh --dry
#   
#   Grab the MaxMind database files. You can download them manually from:
#       - CSV URL: https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key=LICENSE_KEY&suffix=zip
#       - MD5 URL: https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key=LICENSE_KEY&suffix=zip.md5
#   
#   Place your own copies of the csv, or the zip + md5 file which contains the csv; pick ONE of the two:
#       1.  Using CSVs:
#           .github/local/GeoLite2-ASN-Blocks-IPv4.csv
#           .github/local/GeoLite2-ASN-Blocks-IPv6.csv
#       1.  Using ZIPs:
#           .github/local/GeoLite2-ASN-CSV.zip
#           .github/local/GeoLite2-ASN-CSV.zip.md5
#   
#   Dry-run mode is useful for testing or validating the script without hitting the MaxMind servers.
# #

app_file_this=$(basename "$0")                          #  bl-geolite2_asn.sh   (with ext)
app_file_bin="${app_file_this%.*}"                      #  bl-geolite2_asn      (without ext)

# #
#   define > folders
# #

app_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"            #  path where script was last found in
app_dir_this_dir="${PWD}"                               #  current script directory
app_dir_github="${app_dir_this_dir}/.github"            #  .github folder

# #
#   vars > colors
#   
#   Use the color table at:
#       - https://gist.github.com/fnky/458719343aabd01cfb17a3a4f7296797
# #

esc=$(printf '\033')
end="${esc}[0m"
bold="${esc}[1m"
dim="${esc}[2m"
underline="${esc}[4m"
blink="${esc}[5m"
white="${esc}[97m"
black="${esc}[0;30m"
redl="${esc}[0;91m"
redd="${esc}[38;5;196m"
magental="${esc}[0;95m"
magentad="${esc}[0;35m"
fuchsial="${esc}[38;5;205m"
fuchsiad="${esc}[38;5;198m"
bluel="${esc}[38;5;75m"
blued="${esc}[38;5;33m"
greenl="${esc}[38;5;76m"
greend="${esc}[38;5;2m"
orangel="${esc}[0;93m"
oranged="${esc}[38;5;202m"
yellowl="${esc}[38;5;190m"
yellowd="${esc}[38;5;184m"
greyl="${esc}[38;5;250m"
greym="${esc}[38;5;244m"
greyd="${esc}[0;90m"
navy="${esc}[38;5;62m"
olive="${esc}[38;5;144m"
peach="${esc}[38;5;210m"
cyan="${esc}[38;5;6m"

# #
#   define > app
# #

app_name="GeoLite2 Database Script"                                 # name of app
app_desc="This script downloads the asn databases from the MaxMind GeoLite2 servers. \n\n  They are then broken up into their respective ASN files. Duplicates are removed, IPs\n  are re-sorted, and then all files are pushed to the repository."
app_ver="1.2.0.0"                                                   # current script version
app_repo="Aetherinox/csf-firewall"                                  # repository
app_repo_branch="main"                                              # repository branch
app_agent="Mozilla/5.0 (Windows NT 10.0; WOW64) "\
"AppleWebKit/537.36 (KHTML, like Gecko) "\
"Chrome/51.0.2704.103 Safari/537.36"                                # user agent used with curl

# #
#   Args
# #

argDryrun="false"                                                   # Enable dryrun
argASN=""                                                           # Process specific ASN
argUseLocalDB="false"                                               # Process local database instead of download
argMMLicense=""                                                     # MaxMind license key
argLimitEntries=0                                                   # Number of entries to process; set to 0 or unset for full run
argDevMode="false"                                                  # dev mode
argFolder=""
argFile=""
argClean="false"                                                    # geolite2 folder will be wiped before generation
argAggressive="false"

# #
#   define variables
# #

SECONDS=0                                                           # set seconds count for beginning of script
folder_target_storage="blocklists/asn/geolite2"                     # path to save ipsets
folder_target_ext_tmp="tmp"                                         # temp extension for ipsets before work is done
folder_source_local="local"                                         # local mode enabled: where to fetch local csv from
folder_source_temp=".temp"                                          # local mode disabled: where csv will be downloaded to
folder_target_aggressive="@general"                                 # aggressive subfolder
path_storage_ipv4="./${folder_target_storage}/ipv4"                 # folder to store .tmp ipv4 files
path_storage_ipv6="./${folder_target_storage}/ipv6"                 # folder to store .tmp ipv6 files
file_cfg="aetherx.conf"                                             # Optional config file for license key / settings
file_source_ipv4_csv="GeoLite2-ASN-Blocks-IPv4.csv"                 # Geolite2 ASN CSV IPv4
file_source_ipv6_csv="GeoLite2-ASN-Blocks-IPv6.csv"                 # Geolite2 ASN CSV IPv6
file_source_zip_csv="GeoLite2-ASN-CSV.zip"                          # Geolite2 ASN CSV Zip
file_source_zip_csv_md5="${file_source_zip_csv}.md5"                # Geolite2 ASN CSV Zip MD5 hash file
file_target_aggressive="aggressive"                                 # filename to store aggressive list
ext_target_ipset="ipset"                                            # extension for ipsets

# #
#   Color Code Test
#   
#   @usage      .github/scripts/bl-geolite2_asn.sh --color
# #

function debug_ColorTest( )
{
    echo
    echo "  white      ${greym}............. ${white}This is text ███████████████${end}"
    echo "  black      ${greym}............. ${black}This is text ███████████████${end}"
    echo "  redl       ${greym}............. ${redl}This is text ███████████████${end}"
    echo "  redd       ${greym}............. ${redd}This is text ███████████████${end}"
    echo "  magental   ${greym}............. ${magental}This is text ███████████████${end}"
    echo "  magentad   ${greym}............. ${magentad}This is text ███████████████${end}"
    echo "  fuchsial   ${greym}............. ${fuchsial}This is text ███████████████${end}"
    echo "  fuchsiad   ${greym}............. ${fuchsiad}This is text ███████████████${end}"
    echo "  bluel      ${greym}............. ${bluel}This is text ███████████████${end}"
    echo "  blued      ${greym}............. ${blued}This is text ███████████████${end}"
    echo "  greenl     ${greym}............. ${greenl}This is text ███████████████${end}"
    echo "  greend     ${greym}............. ${greend}This is text ███████████████${end}"
    echo "  orangel    ${greym}............. ${orangel}This is text ███████████████${end}"
    echo "  oranged    ${greym}............. ${oranged}This is text ███████████████${end}"
    echo "  yellowl    ${greym}............. ${yellowl}This is text ███████████████${end}"
    echo "  yellowd    ${greym}............. ${yellowd}This is text ███████████████${end}"
    echo "  greyl      ${greym}............. ${greyl}This is text ███████████████${end}"
    echo "  greym      ${greym}............. ${greym}This is text ███████████████${end}"
    echo "  greyd      ${greym}............. ${greyd}This is text ███████████████${end}"
    echo "  navy       ${greym}............. ${navy}This is text ███████████████${end}"
    echo "  olive      ${greym}............. ${olive}This is text ███████████████${end}"
    echo "  peach      ${greym}............. ${peach}This is text ███████████████${end}"
    echo "  cyan       ${greym}............. ${cyan}This is text ███████████████${end}"
    echo

    exit 1
}

# #
#   Helper > Show Color Chart
#   Shows a complete color charge which can be used with the color declarations in this script.
#   
#   @usage      .github/scripts/bt-transmission.sh chart
# #

function debug_ColorChart( )
{
    for fgbg in 38 48 ; do                                  # foreground / background
        for clr in {0..255} ; do                            # colors
            printf "\e[${fgbg};5;%sm  %3s  \e[0m" $clr $clr
            if [ $((($clr + 1) % 6)) == 4 ] ; then          # show 6 colors per lines
                echo
            fi
        done

        echo
    done
    
    exit 1
}

# #
#   func › usage menu
# #

opt_usage( )
{
    echo
    printf "  ${bluel}${app_name}${end}\n" 1>&2
    printf "  ${greym}${app_desc}${end}\n" 1>&2
    printf "  ${greyd}version:${end} ${greyd}$app_ver${end}\n" 1>&2
    printf "  ${fuchsiad}$app_file_this${end} ${greyd}[${greym}--help${greyd}]${greyd}  |  ${greyd}[${greym}--version ${greyd}]${greyd}  |  ${greyd}[${greym}--license ${yellowd}\"${argMMLicense:-"XXXX-0000-XXXXX"}\"${greyd} [${greym}--dryrun${greyd}]]${greyd}  |  ${greyd}[${greym}--local${greyd} [${greym}--limit ${yellowd}\"${argLimitEntries:-"1000"}\"${greyd}]]${end}" 1>&2
    echo
    echo
    printf '  %-5s %-40s\n' "${greyd}Syntax:${end}" "" 1>&2
    printf '  %-5s %-30s %-40s\n' "    " "${greyd}Command${end}           " "${fuchsiad}$app_file_this${greyd} [ ${greym}-option ${greyd}[ ${yellowd}arg${greyd} ]${greyd} ]${end}" 1>&2
    printf '  %-5s %-30s %-40s\n' "    " "${greyd}Options${end}           " "${fuchsiad}$app_file_this${greyd} [ ${greym}-h${greyd} | ${greym}--help${greyd} ]${end}" 1>&2
    printf '  %-5s %-30s %-40s\n' "    " "    ${greym}-A${end}            " " ${white}required" 1>&2
    printf '  %-5s %-30s %-40s\n' "    " "    ${greym}-A...${end}         " " ${white}required; multiple can be specified" 1>&2
    printf '  %-5s %-30s %-40s\n' "    " "    ${greym}[ -A ]${end}        " " ${white}optional" 1>&2
    printf '  %-5s %-30s %-40s\n' "    " "    ${greym}[ -A... ]${end}     " " ${white}optional; multiple can be specified" 1>&2
    printf '  %-5s %-30s %-40s\n' "    " "    ${greym}{ -A | -B }${end}   " " ${white}one or the other; do not use both" 1>&2
    printf '  %-5s %-30s %-40s\n' "    " "${greyd}Arguments${end}         " "${fuchsiad}$app_file_this${end} ${greyd}[ ${greym}-d${yellowd} arg${greyd} | ${greym}--name ${yellowd}arg${greyd} ]${end}${yellowd} arg${end}" 1>&2
    printf '  %-5s %-30s %-40s\n' "    " "${greyd}Examples${end}          " "${fuchsiad}$app_file_this${end} ${greym}--license${yellowd} \"${argMMLicense:-"XXXX-0000-XXXXX"}\" ${end}" 1>&2
    printf '  %-5s %-30s %-40s\n' "    " "${greyd}${end}                  " "${fuchsiad}$app_file_this${end} ${greym}--license${yellowd} \"${argMMLicense:-"XXXX-0000-XXXXX"}\" ${greym}--dryrun${yellowd} ${end}" 1>&2
    printf '  %-5s %-30s %-40s\n' "    " "${greyd}${end}                  " "${fuchsiad}$app_file_this${end} ${greym}--local${yellowd} ${end}" 1>&2
    printf '  %-5s %-30s %-40s\n' "    " "${greyd}${end}                  " "${fuchsiad}$app_file_this${end} ${greym}--local${yellowd} ${greym}--asn${yellowd} \"${argASN:-"7,10"}\" ${end}" 1>&2
    printf '  %-5s %-30s %-40s\n' "    " "${greyd}${end}                  " "${fuchsiad}$app_file_this${end} ${greym}--local${yellowd} ${greym}--limit${yellowd} \"1000\" ${end}" 1>&2
    printf '  %-5s %-30s %-40s\n' "    " "${greyd}${end}                  " "${fuchsiad}$app_file_this${end} ${greyd}[ ${greym}--help${greyd} | ${greym}-h${greyd} | ${greym}/?${greyd} ]${end}" 1>&2
    echo
    printf '  %-5s %-40s\n' "${greyd}Options:${end}" "" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}-l${greyd},${blued}  --license ${yellowd}<string>${end}            " "specifies MaxMind license to download databases ${navy}<default> ${peach}${argMMLicense:-"XXXX-0000-XXXXX"} ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}-o${greyd},${blued}  --local ${yellowd}${end}                      " "install local MaxMind database from zip + md5 or .csv ${navy}<default> ${peach}${argUseLocalDB:-"disabled"} ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}  ${greyd} ${blued}           ${yellowd}${end}                     " "    ${greyd}does not require Maxmind license key ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}  ${greyd} ${blued}           ${yellowd}${end}                     " "    ${greyd}local files must be placed within: ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}  ${greyd} ${blued}           ${yellowd}${end}                     " "    ${greym}1.  Using CSVs: ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}  ${greyd} ${blued}           ${yellowd}${end}                     " "    ${greyd}        ${app_dir_this_dir}/${folder_source_local}/GeoLite2-ASN-Blocks-IPv4.csv ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}  ${greyd} ${blued}           ${yellowd}${end}                     " "    ${greyd}        ${app_dir_this_dir}/${folder_source_local}/GeoLite2-ASN-Blocks-IPv6.csv ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}  ${greyd} ${blued}           ${yellowd}${end}                     " "    ${greym}2.  Using ZIPs: ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}  ${greyd} ${blued}           ${yellowd}${end}                     " "    ${greyd}        ${app_dir_this_dir}/${folder_source_local}/GeoLite2-ASN-CSV.zip ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}  ${greyd} ${blued}           ${yellowd}${end}                     " "    ${greyd}        ${app_dir_this_dir}/${folder_source_local}/GeoLite2-ASN-CSV.zip.md5 ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}-a${greyd},${blued}  --asn ${yellowd}<string>${end}                " "process database and only look for ips with specific ASN ${navy}<default> ${peach}${argASN:-"empty"} ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}-p${greyd},${blued}  --limit ${yellowd}<string>${end}              " "limit number of entries to process and stop ${navy}<default> ${peach}${argLimitEntries:-"0"} ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}  ${greyd} ${blued}           ${yellowd}${end}                     " "    ${greyd}set limit ${fuchsiad}0${end} for no limit ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}-F${greyd},${blued}  --folder ${yellowd}<string>${end}             " "puts ipsets in custom folder; instead of folder using ASN ${navy}<default> ${peach}${argFolder:-"empty"} ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}  ${greyd} ${blued}           ${yellowd}${end}                     " "    ${greyd}must be used with ${olive}--file, -f${end} arg ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}-f${greyd},${blued}  --file ${yellowd}<string>${end}               " "puts ipsets in custom file ${navy}<default> ${peach}${argFile:-"empty"} ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}  ${greyd} ${blued}           ${yellowd}${end}                     " "    ${greyd}must be used with ${olive}--folder, -F${end} arg ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}-a${greyd},${blued}  --aggressive ${yellowd}${end}                 " "specified list will be placed in two files; one being ${fuchsiad}${folder_target_storage}${end} before generating new ipsets ${navy}<default> ${peach}${argClean:-"disabled"} ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}-c${greyd},${blued}  --clean ${yellowd}${end}                      " "wipes all existing files in ${fuchsiad}${folder_target_storage}${end} before generating new ipsets ${navy}<default> ${peach}${argClean:-"disabled"} ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}-u${greyd},${blued}  --usage ${yellowd}${end}                      " "explains how to use this script ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}-p${greyd},${blued}  --paths ${yellowd}${end}                      " "displays the paths that are important to this script ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}-D${greyd},${blued}  --dryrun ${yellowd}${end}                     " "pass dryrun to csf installer script, does not install ${end} ${navy}<default> ${peach}${argDryrun:-"disabled"} ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}-V${greyd},${blued}  --version ${yellowd}${end}                    " "current version of this utilty ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}-d${greyd},${blued}  --dev ${yellowd}${end}                        " "developer mode; verbose logging ${end}" 1>&2
    printf '  %-5s %-81s %-40s\n' "    " "${blued}-h${greyd},${blued}  --help ${yellowd}${end}                       " "show this help menu ${end}" 1>&2
    echo
    echo
}

# #
#   Display help text if command not complete
# #

while [ $# -gt 0 ]; do
    case "$1" in
        -u|--usage)
            echo
            echo "  ${white}To use this script, use one of the following methods:\n"
            echo "  ${greenl}${bold}   License Key / Normal Mode ${end}"
            echo "  ${greym}${bold}   This method requires no files to be added. The asn files will be downloaded from the ${end}"
            echo "  ${greym}${bold}   MaxMind website / servers. ${end}"
            echo "  ${blued}         ./${app_file_this} -l ABCDEF1234567-01234 ${end}"
            echo "  ${blued}         ./${app_file_this} -l ABCDEF1234567-01234 ${end}"
            echo
            echo
            echo "  ${greenl}${bold}   Local Mode .................................................................................................. ${dim}[ Option 1 ] ${end}"
            echo "  ${greym}   This mode allows you to use local copies of the GeoLite2 database files to generate an IP list instead of ${end}"
            echo "  ${greym}   downloading a fresh copy of the .CSV / .ZIP files from the MaxMind website. This method requires you to ${end}"
            echo "  ${greym}   place the .ZIP, and .ZIP.MD5 file in the folder ${oranged}${app_dir_github}/${folder_source_local} ${end}"
            echo
            echo "  ${greym}${bold}   Download the following files from the MaxMind website: ${end}"
            echo "  ${blued}         https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key=LICENSE_KEY&suffix=zip ${end}"
            echo "  ${blued}         https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key=LICENSE_KEY&suffix=zip.md5 ${end}"
            echo
            echo "  ${greym}${bold}   Place the ${greend}.ZIP${end} and ${greend}.ZIP.MD5${end} files in: ${end}"
            echo "  ${blued}         ${app_dir_github}/${folder_source_local} ${end}"
            echo
            echo "  ${greym}${bold}   The filenames MUST be: ${end}"
            echo "  ${blued}         ${app_dir_github}/${folder_source_local}/GeoLite2-ASN-CSV.zip ${end}"
            echo "  ${blued}         ${app_dir_github}/${folder_source_local}/GeoLite2-ASN-CSV.zip.md5 ${end}"
            echo
            echo "  ${greym}${bold}   Run the following command: ${end}"
            echo "  ${blued}         ./${app_file_this} --local ${end}"
            echo "  ${blued}         ./${app_file_this} -o ${end}"
            echo
            echo
            echo "  ${greenl}${bold}   Local Mode .................................................................................................. ${dim}[ Option 2 ] ${end}"
            echo "  ${greym}   This mode allows you to use local copies of the GeoLite2 database files to generate an IP list instead of ${end}"
            echo "  ${greym}   downloading a fresh copy of the .ZIP files from the MaxMind website. This method requires you to extract ${end}"
            echo "  ${greym}   the .ZIP and place the .CSV files in the folder ${oranged}${app_dir_github}/${folder_source_local} ${end}"
            echo
            echo "  ${greym}${bold}   Download the following file from the MaxMind website: ${end}"
            echo "  ${blued}         https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key=LICENSE_KEY&suffix=zip ${end}"
            echo
            echo "  ${greym}${bold}   Open the .ZIP and extract the following files to the folder ${oranged}${app_dir_github}/${folder_source_local} ${end}"
            echo "  ${blued}         ${app_dir_github}/${folder_source_local}/GeoLite2-ASN-Blocks-IPv4.csv ${end}"
            echo "  ${blued}         ${app_dir_github}/${folder_source_local}/GeoLite2-ASN-Blocks-IPv6.csv ${end}"
            echo
            echo "  ${greym}${bold}   Run the following command: ${end}"
            echo "  ${blued}         ./${app_file_this} --local ${end}"
            echo "  ${blued}         ./${app_file_this} -o ${end}"
            echo
            echo
            echo "  ${greenl}${bold}   Dry Run ..................................................................................................... ${end}"
            echo "  ${greym}   This mode allows you to simulate downloading the .ZIP files from the MaxMind website. However, the CURL ${end}"
            echo "  ${greym}   commands will not actually be ran. Instead, the script will look for the needed database files in the ${end}"
            echo "  ${greym}   ${folder_source_temp} folder. This method requires you to place either the .ZIP & .ZIP.MD5 files, or extracted CSV files ${end}"
            echo "  ${greym}   in the folder ${oranged}${app_dir_github}/${folder_source_temp} ${end}"
            echo
            echo "  ${greym}${bold}   Place the .ZIP & .MD5 file, OR the .CSV files in the folder ${oranged}${app_dir_github}/${folder_source_temp} ${end}"
            echo "  ${blued}         ${app_dir_github}/${folder_source_temp}/GeoLite2-ASN-Blocks-IPv4.csv ${end}"
            echo "  ${blued}         ${app_dir_github}/${folder_source_temp}/GeoLite2-ASN-Blocks-IPv6.csv ${end}"
            echo
            echo "  ${blued}         ${app_dir_github}/${folder_source_temp}/GeoLite2-ASN-CSV.zip ${end}"
            echo "  ${blued}         ${app_dir_github}/${folder_source_temp}/GeoLite2-ASN-CSV.zip.md5 ${end}"
            echo
            echo "  ${greym}${bold}   Run the following command: ${end}"
            echo "  ${blued}         ./${app_file_this} --dry${end}"
            echo "  ${blued}         ./${app_file_this} -d${end}"
            echo
            exit 1
            ;;
        -p|--paths)
            echo
            echo "  ${white}List of paths important to this script:"
            echo "  ${greenl}📁 ${bold}${oranged}${app_dir_github}/${folder_source_local} ${end}"
            echo "  ${greym}    Folder used when Local Mode enabled ${greend}(--local) ${end}"
            echo "  ${greym}        Can detect GeoLite2 ${blued}.ZIP${greym} and ${blued}.ZIP.MD5${greym} files ${end}"
            echo "  ${greym}        Can detect GeoLite2 ${blued}.CSV${greym} location and IPv4/IPv6 files ${end}"
            echo
            echo
            echo "  ${greenl}📁 ${bold}${oranged}${app_dir_github}/${folder_source_temp} ${end}"
            echo "  ${greym}    Folder used when Dry Run enabled ${greend}(--dry) ${end}"
            echo "  ${greym}        Can detect GeoLite2 ${blued}.ZIP${greym} and ${blued}.ZIP.MD5${greym} files ${end}"
            echo "  ${greym}        Can detect GeoLite2 ${blued}.CSV${greym} location and IPv4/IPv6 files ${end}"
            echo
            echo
            exit 1
            ;;
        -l|--license|--key)
            case "$1" in
                *=*)
                    argMMLicense=$(echo "$1" | cut -d= -f2)
                    ;;
                *)
                    shift
                    argMMLicense="$1"
                    ;;
            esac

            if [ -z "${argMMLicense}" ]; then
                echo
                echo "  Specifies your MaxMind license key."
                echo "  Required if you are not running the script in local mode."
                echo "  Example: ./${app_file_this} -l ABCDEF1234567-01234"
                echo
                exit 1
            fi
            ;;
        -L|--limit)
            case "$1" in
                *=*)
                    argLimitEntries=$(echo "$1" | cut -d= -f2)
                    ;;
                *)
                    shift
                    argLimitEntries="$1"
                    ;;
            esac
            ;;
        -F|--folder)
            case "$1" in
                *=*)
                    argFolder=$(echo "$1" | cut -d= -f2)
                    ;;
                *)
                    shift
                    argFolder="$1"
                    ;;
            esac

            if [ -z "${argFolder}" ]; then
                echo
                echo "  You must provide a valid folder"
                echo "  Example: ./${app_file_this} --folder=c"
                echo
                exit 1
            fi
            ;;
        -f|--file)
            case "$1" in
                *=*)
                    argFile=$(echo "$1" | cut -d= -f2)
                    ;;
                *)
                    shift
                    argFile="$1"
                    ;;
            esac

            if [ -z "${argFile}" ]; then
                echo
                echo "  You must provide a valid folder"
                echo "  Example: ./${app_file_this} --file=cloudflare"
                echo
                exit 1
            fi
            ;;
        -a|--asn)
            argASN=""
            shift
            while [ $# -gt 0 ] && [[ "$1" != -* ]]; do
                # #
                #   append current token with a space
                # #

                argASN="$argASN $1"
                shift
            done

            argASN="${argASN#"${argASN%%[! ]*}"}"  # trim leading spaces

            if [ -z "$argASN" ]; then
                echo "No ASN specified"
                exit 1
            fi

            # #
            #   remove AS/ASN, replace spaces with commas
            # #

            argASN=$(echo "$argASN" \
                | tr '[:upper:]' '[:lower:]' \
                | sed 's/asn\{0,1\}//g; s/[^0-9, ]//g; s/[[:space:]]\+/,/g; s/,,*/,/g; s/^,//; s/,$//')
            IFS=',' read -ra FILTER_ASNS <<< "$argASN"
            ;;
        -c|--clean)
            argClean=true
            echo "  ${redl}Cleaning storage folder ${folder_target_storage} ${end}"
            ;;
        -d|--dev|--debug)
            argDevMode=true
            echo "    ⚠️ Debug Mode › ${blink}${greyd}enabled${greym}${end}"
            ;;
        -o|--local)
            argUseLocalDB=true
            echo "  Local Mode Enabled"
            ;;
        --dry|--dryrun)
            argDryrun=true
            echo "  Dry Run Enabled"
            ;;
        -a|--aggressive)
            argAggressive=true
            ;;
        -v|--version)
            echo
            echo "  ${blued}${bold}${APP_NAME}${end} - v$app_ver ${end}"
            echo "  ${greenl}${bold}https://github.com/${app_repo} ${end}"
            echo
            exit 1
            ;;
        -C|--color)
            debug_ColorTest
            exit 1
            ;;
        -G|--graph|--chart)
            debug_ColorChart
            exit 1
            ;;
        -\?|-h|--help)
            opt_usage
            exit 1
            ;;
        *)
            printf '%-28s %-65s\n' "  ${redl} ERROR ${end}" "${greym} Unknown parameter:${redl} $1 ${greym}. Aborting ${end}"
            exit 1
            ;;
    esac
    shift
done

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
#   Prints single line, no text
#   
#   @usage          prin0
# #

prin0()
{
    local indent="   "
    local box_width=110
    local line_width=$(( box_width + 2 ))

    local line
    line=$(printf '─%.0s' $(seq 1 "$line_width"))

    print
    printf "%b%s%s%b\n" "${greyd}" "$indent" "$line" "${reset}"
    print
}

# #
#   Print › Box › Crop
#   
#   Prints single line with a box surrounding it, excluding the right side
#   
#   @usage          princ "Name › Section"
# #

princ()
{
    local title="$*"
    local indent="   "
    local padding=6
    
    local visible_title
    visible_title=$(echo -e "$title" | sed 's/\x1b\[[0-9;]*m//g')
    
    local title_length=${#visible_title}
    local inner_width=$(( title_length + padding ))
    local box_width=110

    [ "$inner_width" -lt ${box_width} ] && inner_width=${box_width}

    local line
    line=$(printf '─%.0s' $(seq 1 "$inner_width"))

    local spaces_needed=$(( inner_width - title_length - 3 ))
    local spaces=$(printf ' %.0s' $(seq 1 "$spaces_needed"))

    print
    printf "%b%s┌%s┐\n" "${greym}" "$indent" "$line"
    printf "%b%s│  %s%s \n" "${greym}" "$indent" "$title" "$spaces"
    printf "%b%s└%s┘%b\n" "${greym}" "$indent" "$line" "${reset}"
    print
}

# #
#   Print › Box › Single
#   
#   Prints single line with a box surrounding it.
#   
#   @usage          prinb "${APP_NAME_SHORT:-CSF} › Customize csf.config"
# #

prinb( )
{
    # #
    #   Dynamic boxed title printer
    # #

    local title="$*"
    local indent="   "                              # Left padding
    local padding=6                                 # Extra horizontal space around text
    local title_length=${#title}
    local inner_width=$(( title_length + padding ))
    local box_width=110

    # #
    #   Minimum width for aesthetics
    # #

    [ "$inner_width" -lt ${box_width} ] && inner_width=${box_width}

    # #
    #   Horizontal border
    # #

    local line
    line=$(printf '─%.0s' $(seq 1 "$inner_width"))

    # #
    #   Draw box
    # #

    print
    print
    printf "%b%s┌%s┐\n" "${greym}" "$indent" "$line"
    printf "%b%s│  %-${inner_width}s \n" "${greym}" "$indent" "$title"
    printf "%b%s└%s┘%b\n" "${greym}" "$indent" "$line" "${reset}"
    print
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
#   Define
# #

readonly CONFIGS_LIST="${APP_GEO_LOCS_CSV} ${file_source_ipv4_csv} ${file_source_ipv6_csv}"

# #
#   Sort IP Addresses
#   
#   @usage      line=$(parse_spf_record "${ip}" | ipSort)
# #

ipSort()
{
    ipv4_tmp=$(mktemp) || exit 1
    ipv6_tmp=$(mktemp) || exit 1

    # Read input line by line
    while IFS= read -r line; do
        case "${line}" in
            *:*)
                printf '%s\n' "${line}" >> "${ipv6_tmp}"
                ;;
            *)
                printf '%s\n' "${line}" >> "${ipv4_tmp}"
                ;;
        esac
    done

    # Sort IPv4 if file is not empty
    if [ -s "${ipv4_tmp}" ]; then
        sort -t. -g -k1,1 -k2,2 -k3,3 -k4,4 "${ipv4_tmp}" | uniq
    fi

    # Sort IPv6 if file is not empty
    if [ -s "${ipv6_tmp}" ]; then
        sort -t: -g -k1,1 -k2,2 -k3,3 -k4,4 -k5,5 -k6,6 -k7,7 -k8,8 "${ipv6_tmp}" | uniq
    fi

    # Cleanup
    rm -f "${ipv4_tmp}" "${ipv6_tmp}"
    if [ ! -d "${ipv4_tmp}" ]; then
        ok "    🗑️  Removed folder ${greenl}${ipv4_tmp}"
    else
        error "    ❌ Failed to remove folder ${redl}${ipv4_tmp}"
    fi

    if [ ! -d "${ipv6_tmp}" ]; then
        ok "    🗑️  Removed folder ${greenl}${ipv6_tmp}"
    else
        error "    ❌ Failed to remove folder ${redl}${ipv6_tmp}"
    fi
}

# #
#   ensure the programs needed to execute are available
# #

required_Packages()
{
    PKG="awk cat curl sed md5sum mktemp unzip"

    for cmd in $PKG; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            error "    ❌ Required dependency not found in PATH: ${redl}${cmd}"
        fi
    done
}

# #
#   Get latest MaxMind GeoLite2 IP asn database and md5 checksum
#       CSV URL: https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key=LICENSE_KEY&suffix=zip
#       MD5 URL: https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key=LICENSE_KEY&suffix=zip.md5
#   
#   If using --dry, you must manually download the .zip and .zip.md5 files and place them in the local folder assigned to the value
#       $folder_source_local
# #

function maxmind_Database_Download( )
{

    info "    📦 Getting ready to download MaxMind databases${greym}"

    local URL_CSV="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key=${argMMLicense}&suffix=zip"
    local URL_MD5="${URL_CSV}.md5" # Take URL_CSV value and add .md5 to end for hash file

    # #
    #   download files
    #       - will not download if --dryrun specified
    #       - will not download if --local specified
    # #

    if [ "${argDryrun}" != "true" ] && [ "${argUseLocalDB}" != "true" ]; then
        URL_HIDDEN_CSV=$(printf '%s\n' "${URL_CSV}" | sed "s/${argMMLicense}/HIDDEN/g")
        URL_HIDDEN_MD5=$(printf '%s\n' "${URL_MD5}" | sed "s/${argMMLicense}/HIDDEN/g")

        info "    🌎 Downloading ${bluel}${file_source_zip_csv}${end} from ${bluel}${URL_HIDDEN_CSV}"
        if ! curl --silent --show-error --location \
                --user-agent "${app_agent}" \
                --output "${file_source_zip_csv}" "${URL_CSV}"
        then
            error "    ❌ Failed to curl database files from ${redl}${URL_HIDDEN_CSV}${greym}"
        fi

        info "    🌎 Downloading ${bluel}${file_source_zip_csv_md5}${end} from ${bluel}${URL_HIDDEN_MD5}"
        if ! curl --silent --show-error --location \
                --user-agent "${app_agent}" \
                --output "${file_source_zip_csv_md5}" "${URL_MD5}"
        then
            error "    ❌ Failed to curl database files from ${redl}${URL_HIDDEN_MD5}${greym}"
        fi
    fi

    # #
    #   .CSV missing, warn user to provide one or the other
    # #

    if [ ! -f "${file_source_zip_csv}" ]; then
        error "    ❌ Must supply zip ${redl}${file_source_zip_csv}${greym} + md5 ${redl}${file_source_zip_csv_md5}${greym}; cannot locate"
    fi

    # #
    #   Provided the .ZIP, but not the ZIP hash file
    # #

    if [ -f "${file_source_zip_csv}" ] && [ ! -f "${file_source_zip_csv_md5}" ]; then
        error "    ❌ You supplied zip ${redl}${file_source_zip_csv}${greym}, but did not provide the md5 file ${redl}${file_source_zip_csv_md5}${greym}; cannot continue"
    fi

    # #
    #   Provided IPv4 csv file, but may be missing the others
    # #

    if [ -f "${file_source_ipv4_csv}" ]; then
        if [ ! -f "${file_source_ipv6_csv}" ]; then
            error "    ❌ You supplied IPv4 CSV ${redl}${file_source_ipv4_csv}${greym}, but did not provide IPv6 CSV file ${redl}${file_source_ipv6_csv}${greym}; cannot continue"
        fi
    fi

    # #
    #   Provided IPv6 csv file, but may be missing the others
    # #

    if [ -f "${file_source_ipv6_csv}" ]; then
        if [ ! -f "${file_source_ipv4_csv}" ]; then
            error "    ❌ You supplied IPv6 CSV ${redl}${file_source_ipv6_csv}${greym}, but did not provide IPv4 CSV file ${redl}${file_source_ipv4_csv}${greym}; cannot continue"
        fi
    fi

    # #
    #   Zip files provided, check MD5
    # #

    if [ -f "${file_source_zip_csv}" ] && [ -f "${file_source_zip_csv_md5}" ]; then

        info "    📄 Found ASN .zip database ${bluel}${file_source_zip_csv}${greym} and ${bluel}${file_source_zip_csv_md5}${greym}"

        # #
        #   Check for download limit reached
        # #

        md5Response=$(cat "${file_source_zip_csv_md5}")
        case "$md5Response" in
            *"download limit reached"*)
                error "    ❌ MaxMind: Daily API download limit reached"
                ;;
        esac

        # #
        #   Validate checksum
        #   .md5 file is not in expected format; 'md5sum --check' won't work
        # #

        md5_local=$(md5sum "${TEMPDIR}/${file_source_zip_csv}" | awk '{print $1}')
        if [ "$md5Response" != "$md5_local" ]; then
            error "    ❌ GeoLite2 MD5 downloaded checksum does not match local md5 checksum"
        fi

        # #
        #   Unzip into current working directory
        # #

        if [ -f "${file_source_zip_csv}" ]; then

            info "    📦 Found zip ${bluel}${file_source_zip_csv}${greym}"
            if unzip -o -j -q -d . "${file_source_zip_csv}"; then
                ok "    📦 Unzip successful ${greenl}${file_source_zip_csv}"
            else
                error "    ❌ Unzip failed ${redl}${file_source_zip_csv}${greym}, aborting${greym}"
                exit 1
            fi
        else
            error "    ❌ Cannot locate zip ${redl}${file_source_zip_csv}"
        fi

    elif [ -f "${APP_GEO_LOCS_CSV}" ] && [ -f "${file_source_ipv4_csv}" ] && [ -f "${file_source_ipv6_csv}" ]; then
        info "    📄 Found Uncompressed set ${bluel}${APP_GEO_LOCS_CSV}${greym},${bluel}${file_source_ipv4_csv}${greym} and ${bluel}${file_source_ipv6_csv}${greym}"
    else
        error "    ❌ Could not locate either ${redl}zip + md5${greym} or ${redl}uncompressed csv${greym}"
    fi

}

# #
#   Maxmind › Load Database
#   
#   Database can either be provided locally, or downloaded from the MaxMind site.
#   This func covers local loading.
# #

function maxmind_Database_Load( )
{

    info "    📄 Load ASN Database Files${greym}"

    # #
    #   Called from
    #       readonly CONFIGS_LIST="${APP_GEO_LOCS_CSV} ${file_source_ipv4_csv} ${file_source_ipv6_csv}"
    # #

    local configs=(${CONFIGS_LIST})
    for f in ${configs[@]}; do

        info "    📄 Mounting ASN file ${blued}${TEMPDIR}/${f}"
        if [ ! -f "$f" ]; then
            error "    ❌ Missing ASN database: ${redl}${TEMPDIR}/${f}${greym}"
        fi
    done
}

# #
#   Generate › IPv4
# #

function generate_IPv4
{
    info "    📟 Generate ${bluel}IPv4${greym} ipsets from ASN database"

    # #
    #   remove existing ipv4 folder:
    #       blocklists/asn/geolite2/ipv4/
    # #

    rm -rf "${path_storage_ipv4}"
    if [ ! -d "${path_storage_ipv4}" ]; then
        ok "    🗑️  Removed folder ${bluel}${path_storage_ipv4}"
    else
        error "    ❌ Failed to remove folder ${greenl}${path_storage_ipv4}"
    fi

    # #
    #   Create new ipv4 folder:
    #       blocklists/asn/geolite2/ipv4/
    # #

    if [ ! -d "${path_storage_ipv4}" ]; then
        mkdir -p "${path_storage_ipv4}"

        if [ -d "${path_storage_ipv4}" ]; then
            ok "    📂 Created ${greenl}${path_storage_ipv4}"
        else
            error "    ❌ Failed to create ${redl}${path_storage_ipv4}"
        fi
    fi

    # #
    #   Start import
    # #

    info "    ➕ Importing ${bluel}IPv4${greym} from ASN database"

    # #
    #   Pre-split ASN filter once if provided
    #       argASN can be formatted as:
    #           .github/scripts/bl-geolite2_asn_custom.sh --local --asn AS49581 AS212513
    # #

    IFS=',' read -ra FILTER_ASNS <<< "${argASN:-}"

    # #
    #   Track created folders to avoid repeated mkdir
    # #

    declare -A created_folders

    count=0
    bShowMessageASN="true"
    bShowMessageARG="true"

    while IFS=',' read -r ipset_read_subnet ipset_read_asn ipset_read_orgname _; do
        ((count++))
        [[ $argLimitEntries -gt 0 && $count -gt $argLimitEntries ]] && break
        [[ -z "${ipset_read_subnet}" || -z "${ipset_read_asn}" ]] && continue

        # #
        #   Filter by specific ASN if needed
        # #
    
        if [ "${#FILTER_ASNS[@]}" -gt 0 ]; then

            if [ "$bShowMessageASN" = "true" ]; then
                debug "    ➕ Custom list of ASNs provided using --asn, -a"
                bShowMessageASN="false"
            fi

            match=false
            OLD_IFS=$IFS
            IFS=','
    
            for asn in $argASN; do
                if [ "${ipset_read_asn}" = "$asn" ]; then
                    match=true
                    break
                fi
            done
    
            IFS=$OLD_IFS

            [ "$match" = true ] || continue
        fi

        #   debug "    ➕ Start Process ${bluel}${ipset_read_subnet}${greym} › ASN ${bluel}${ipset_read_asn}${greym} › Org ${bluel}${ipset_read_orgname}${greym}${greym}"

        # #
        #   Clean org name. Transform to lower-case, strip special chars.
        #   Will be used as folder name
        # #

        ipset_orgname=$(echo "${ipset_read_orgname}" \
            | tr '[:upper:]' '[:lower:]' \
            | sed 's/[^a-z0-9]/_/g; s/_\+/_/g; s/^_//; s/_$//')

        # #
        #   If flags are used:
        #       --folder=, --arg=
        # #

        if [[ -n "${argFolder}" && -n "${argFile}" ]]; then

            if [ "${bShowMessageARG}" = "true" ]; then
                debug "    📂 Args --folder, --file specified, generating subfolder"
                bShowMessageARG="false"
            fi

            # #
            #   Create top-level folder
            #       blocklists/asn/geolite2/ipv4/FOLDERNAME
            # #
        
            top_folder="${argFolder}"
            path_ipset_subfolder="${path_storage_ipv4}/${top_folder}"

            if [ ! -d "${path_ipset_subfolder}" ]; then
                mkdir -p "${path_ipset_subfolder}"

                if [ -d "${path_ipset_subfolder}" ]; then
                    ok "    📂 Created ${greenl}${path_ipset_subfolder}"
                else
                    error "    ❌ Failed to create ${redl}${path_ipset_subfolder}"
                fi
            fi

            path_ipset="${path_ipset_subfolder}/${argFile}.${folder_target_ext_tmp}"

        # #
        #   --folder=, --file= not specified
        #   Default to normal folder naming scheme.
        # #

        else
            if [ "${bShowMessageARG}" = "true" ]; then
                debug "    📂 Missing args --folder, --file, using ASN grouping subfolder structure"
                bShowMessageARG="false"
            fi

            # #
            #   Default numeric grouping
            #   
            #   If --asn=4564 is provided; folder name will be 4000
            #   If --asn=53924 is provided, folder name will be 53000
            # #
        
            folder_asn_group=$((ipset_read_asn / 1000 * 1000))
            path_ipset_subfolder="${path_storage_ipv4}/${folder_asn_group}"

            # #
            #   Folder doesn't exist, create
            # #

            if [[ -z "${created_folders[${path_ipset_subfolder}]}" ]]; then

                if [ ! -d "${path_ipset_subfolder}" ]; then
                    mkdir -p "${path_ipset_subfolder}"

                    if [ -d "${path_ipset_subfolder}" ]; then
                        ok "    📂 Created ${greenl}${path_ipset_subfolder}"
                    else
                        error "    ❌ Failed to create ${redl}${path_ipset_subfolder}"
                    fi
                fi

                created_folders[${path_ipset_subfolder}]=1
            fi
            path_ipset="${path_ipset_subfolder}/asn_${ipset_read_asn}_${ipset_orgname}.${folder_target_ext_tmp}"
        fi

        debug "    ➕ Adding IP/Subnet › IP ${bluel}${ipset_read_subnet}${greym} › ASN ${bluel}${ipset_read_asn}${greym} › Org ${bluel}${ipset_read_orgname}${greym} › File ${bluel}${path_ipset}${greym}"

        # #
        #   add ASN and OrgName to top of file as placeholder, will be used to generate header at end 
        #   and the existing META_ lines will be removed.
        # #

        if [ ! -f "${path_ipset}" ]; then
            {
                echo "# META_ASN=${ipset_read_asn}"
                echo "# META_ORG=${ipset_read_orgname}"
            } >> "${path_ipset}"
        fi

        # #
        #   Write ip / subnet to file
        # #

        echo "${ipset_read_subnet}" >> "${path_ipset}"

        # #
        #   Append to aggressive raw if --aggressive
        # #

        if [ "${argAggressive}" = "true" ]; then
            aggressive_raw="${folder_target_storage}/${folder_target_aggressive}/${file_target_aggressive}.${folder_target_ext_tmp}"
            mkdir -p "$(dirname "${aggressive_raw}")"
            echo "${ipset_read_subnet}" >> "${aggressive_raw}"
        fi

    done < <(tail -n +2 "${TEMPDIR}/${file_source_ipv4_csv}")
}

# #
#   Generate › IPv6
# #

function generate_IPv6
{
    info "    📟 Generate ${bluel}IPv6${greym} ipsets from ASN database"

    # #
    #   remove existing ipv4 folder:
    #       blocklists/asn/geolite2/ipv4/
    # #

    rm -rf "${path_storage_ipv6}"
    if [ ! -d "${path_storage_ipv6}" ]; then
        ok "    🗑️  Removed folder ${bluel}${path_storage_ipv6}"
    else
        error "    ❌ Failed to remove folder ${greenl}${path_storage_ipv6}"
    fi

    # #
    #   Create new ipv6 folder:
    #       blocklists/asn/geolite2/ipv6/
    # #

    if [ ! -d "${path_storage_ipv6}" ]; then
        mkdir -p "${path_storage_ipv6}"

        if [ -d "${path_storage_ipv6}" ]; then
            ok "    📂 Created ${greenl}${path_storage_ipv6}"
        else
            error "    ❌ Failed to create ${redl}${path_storage_ipv6}"
        fi
    fi

    # #
    #   Start import
    # #

    info "    ➕ Importing ${bluel}IPv6${greym} from ASN database"

    # #
    #   Pre-split ASN filter once if provided
    #       argASN can be formatted as:
    #           .github/scripts/bl-geolite2_asn_custom.sh --local --asn AS49581 AS212513
    # #

    IFS=',' read -ra FILTER_ASNS <<< "${argASN:-}"

    # #
    #   Track created folders to avoid repeated mkdir
    # #

    declare -A created_folders

    count=0
    bShowMessageASN="true"
    bShowMessageARG="true"

    while IFS=',' read -r ipset_read_subnet ipset_read_asn ipset_read_orgname _; do
        ((count++))
        [[ $argLimitEntries -gt 0 && $count -gt $argLimitEntries ]] && break
        [[ -z "${ipset_read_subnet}" || -z "${ipset_read_asn}" ]] && continue

        # #
        #   Filter by specific ASN if needed
        # #
    
        if [ "${#FILTER_ASNS[@]}" -gt 0 ]; then

            if [ "$bShowMessageASN" = "true" ]; then
                debug "    ➕ Custom list of ASNs provided using --asn, -a"
                bShowMessageASN="false"
            fi

            match=false
            OLD_IFS=$IFS
            IFS=','
    
            for asn in $argASN; do
                if [ "${ipset_read_asn}" = "$asn" ]; then
                    match=true
                    break
                fi
            done
    
            IFS=$OLD_IFS

            [ "$match" = true ] || continue
        fi

        #   debug "    ➕ Start Process ${bluel}${ipset_read_subnet}${greym} › ASN ${bluel}${ipset_read_asn}${greym} › Org ${bluel}${ipset_read_orgname}${greym}${greym}"

        # #
        #   Clean org name. Transform to lower-case, strip special chars.
        #   Will be used as folder name
        # #

        ipset_orgname=$(echo "${ipset_read_orgname}" \
            | tr '[:upper:]' '[:lower:]' \
            | sed 's/[^a-z0-9]/_/g; s/_\+/_/g; s/^_//; s/_$//')

        # #
        #   If flags are used:
        #       --folder=, --arg=
        # #

        if [[ -n "${argFolder}" && -n "${argFile}" ]]; then
    
            if [ "${bShowMessageARG}" = "true" ]; then
                debug "    📂 Args --folder, --file specified, generating subfolder"
                bShowMessageARG="false"
            fi

            # #
            #   Create top-level folder
            #       blocklists/asn/geolite2/ipv4/FOLDERNAME
            # #
        
            top_folder="${argFolder}"
            path_ipset_subfolder="${path_storage_ipv6}/${top_folder}"

            if [ ! -d "${path_ipset_subfolder}" ]; then
                mkdir -p "${path_ipset_subfolder}"

                if [ -d "${path_ipset_subfolder}" ]; then
                    ok "    📂 Created ${greenl}${path_ipset_subfolder}"
                else
                    error "    ❌ Failed to create ${redl}${path_ipset_subfolder}"
                fi
            fi

            path_ipset="${path_ipset_subfolder}/${argFile}.${folder_target_ext_tmp}"

        # #
        #   --folder=, --file= not specified
        #   Default to normal folder naming scheme.
        # #

        else
            if [ "${bShowMessageARG}" = "true" ]; then
                debug "    📂 Missing args --folder, --file, using ASN grouping subfolder structure"
                bShowMessageARG="false"
            fi

            # #
            #   Default numeric grouping
            #   
            #   If --asn=4564 is provided; folder name will be 4000
            #   If --asn=53924 is provided, folder name will be 53000
            # #

            folder_asn_group=$((ipset_read_asn / 1000 * 1000))
            path_ipset_subfolder="${path_storage_ipv6}/${folder_asn_group}"

            # #
            #   Folder doesn't exist, create
            # #

            if [[ -z "${created_folders[${path_ipset_subfolder}]}" ]]; then

                if [ ! -d "${path_ipset_subfolder}" ]; then
                    mkdir -p "${path_ipset_subfolder}"

                    if [ -d "${path_ipset_subfolder}" ]; then
                        ok "    📂 Created ${greenl}${path_ipset_subfolder}"
                    else
                        error "    ❌ Failed to create ${redl}${path_ipset_subfolder}"
                    fi
                fi

                created_folders[${path_ipset_subfolder}]=1
            fi
            path_ipset="${path_ipset_subfolder}/asn_${ipset_read_asn}_${ipset_orgname}.${folder_target_ext_tmp}"
        fi

        debug "    ➕ Adding IP/Subnet › IP ${bluel}${ipset_read_subnet}${greym} › ASN ${bluel}${ipset_read_asn}${greym} › Org ${bluel}${ipset_read_orgname}${greym} › File ${bluel}${path_ipset}${greym}"

        # #
        #   add ASN and OrgName to top of file as placeholder, will be used to generate header at end 
        #   and the existing META_ lines will be removed.
        # #

        if [ ! -f "${path_ipset}" ]; then
            {
                echo "# META_ASN=${ipset_read_asn}"
                echo "# META_ORG=${ipset_read_orgname}"
            } >> "${path_ipset}"
        fi

        # #
        #   write ip / subnet to file
        # #

        echo "${ipset_read_subnet}" >> "${path_ipset}"

        # #
        #   Append to aggressive raw if --aggressive
        # #

        if [ "${argAggressive}" = "true" ]; then
            aggressive_raw="${folder_target_storage}/${folder_target_aggressive}/${file_target_aggressive}.${folder_target_ext_tmp}"
            mkdir -p "$(dirname "${aggressive_raw}")"
            echo "${ipset_read_subnet}" >> "${aggressive_raw}"
        fi

    done < <(tail -n +2 "${TEMPDIR}/${file_source_ipv6_csv}")
}

# #
#   Ipsets › Merge
#   
#   Merge IPv4 and IPv6 Files
#   
#   Takes all of the ipv6 addresses and merges them with the ipv4 file.
#       blocklists/country/geolite/ipv6/AD.tmp  =>  blocklists/country/geolite/ipv4/AD.tmp
#       [ DELETED ]                             =>                         [ MERGED WITH ]
#   
#   Removes the ipv6 file after the merge is done.
# #

function ipsets_Merge()
{
    echo

    info "    🔀 Merge › Start"

    # #
    #   Recursively find all IPv6 tmp files
    # #

    find "${path_storage_ipv6}" -type f -name "*.${folder_target_ext_tmp}" | while read fullpath_ipv6; do
        file_ipv6=$(basename "${fullpath_ipv6}")
        dest_dir="${path_storage_ipv4}/$(basename $(dirname "${fullpath_ipv6}"))"

        if [ ! -d "${dest_dir}" ]; then
            mkdir -p "${dest_dir}"

            if [ -d "${dest_dir}" ]; then
                ok "    📂 Created ${greenl}${dest_dir}"
            else
                error "    ❌ Failed to create ${redl}${dest_dir}"
            fi
        fi

        # #
        #   merge ipv5 temp with perm file
        # #

        info "    🔀 Merge › ${bluel}${fullpath_ipv6}${end} › ${bluel}${dest_dir}/${file_ipv6}"
        cat "${fullpath_ipv6}" >> "${dest_dir}/${file_ipv6}"
        
        # #
        #   delete old ipv6 temp folder
        # #

        rm -f "${fullpath_ipv6}"
        if [ ! -d "${fullpath_ipv6}" ]; then
            ok "    🗑️  Removed folder ${greenl}${fullpath_ipv6}"
        else
            error "    ❌ Failed to remove folder ${redl}${fullpath_ipv6}"
        fi
    done
}

# #
#   Ipsets › Finalize
#   
#   move .tmp files to .ipset
#   also generates @/aggressive.ipset if --aggressive is used
# #

function ipsets_Finalize()
{
    echo

    info "    🚛 Finalize › Start"
    label "       Moving staged .tmp files to final ${bluel}.${ext_target_ipset}${greym} files"

    # #
    #   Ensure permanent storage directory exists.
    #   Location where finalized ipset files are written to.
    #       blocklists/asn/geolite2
    # #

    if [ ! -d "${folder_target_storage}" ]; then
        mkdir -p "${folder_target_storage}"
        if [ -d "${folder_target_storage}" ]; then
            ok "    📂 Created ${greenl}${folder_target_storage}"
        else
            error "    ❌ Failed to create ${redl}${folder_target_storage}"
        fi
    fi

    # #
    #   Aggressive mode paths
    #   
    #       aggressive_raw      › temporary merged list (pre-dedup)
    #       aggressive_file     › final aggressive ipset file
    # #

    aggressive_raw="${folder_target_storage}/${folder_target_aggressive}/${file_target_aggressive}.${folder_target_ext_tmp}"
    aggressive_file="${folder_target_storage}/${folder_target_aggressive}/${file_target_aggressive}.${ext_target_ipset}"
    
    # #
    #   Remove any existing aggressive output file.
    #   Ensures a clean rebuild every run.
    # #

    if [ -f "${aggressive_file}" ]; then
        rm -f "${aggressive_file}"
        if [ ! -d "${aggressive_file}" ]; then
            ok "    🗑️  Removed folder ${greenl}${aggressive_file}"
        else
            error "    ❌ Failed to remove folder ${redl}${aggressive_file}"
        fi
    fi

    # #
    #   Process both IPv4 and IPv6 staging directories.
    #   Create each of the .tmp files being processed.
    # #

    for DIR in "${path_storage_ipv4}" "${path_storage_ipv6}"; do
        if [ -d "${DIR}" ]; then

            # #
            #   Iterate recursively over all .tmp files.
            #   These are converted from .tmp to final .ipset files
            # #

            while IFS= read -r -d '' tmpfile; do
                relative_subfolder=$(dirname "${tmpfile#${DIR}/}")
                target_dir="${folder_target_storage}/${relative_subfolder}"
                mkdir -p "${target_dir}"
                if [ -d "${target_dir}" ]; then
                    ok "    📂 Created ${greenl}${target_dir}"
                else
                    error "    ❌ Failed to create ${redl}${target_dir}"
                fi

                # #
                #   Build final filename
                #   Strips .tmp extension and replaces with .ipset
                # #

                basename_tmp=$(basename "${tmpfile}" .${folder_target_ext_tmp})
                target_file="${target_dir}/${basename_tmp}.${ext_target_ipset}"

                # #
                #   Count statistics for header metadata
                #       › total_lines       non-comment entries
                #       › total_subnets     number of CIDR entries
                #       › total_ips         estimated IP count
                # #

                total_lines=0
                total_subnets=0
                total_ips=0
                while IFS= read -r subnet || [ -n "${subnet}" ]; do
                    [[ -z "${subnet}" ]] && continue
                    case "${subnet}" in \#*|\;*) continue ;; esac
                    total_lines=$(( total_lines + 1 ))
                    total_subnets=$(( total_subnets + 1 ))
                    case "${subnet}" in
                        *:* ) total_ips=$(( total_ips + 1 )) ;;
                        */* )
                            prefix=${subnet##*/}
                            if [[ "${prefix}" =~ ^[0-9]+$ ]] && [ "${prefix}" -ge 0 ] && [ "${prefix}" -le 32 ]; then
                                total_ips=$(( total_ips + (1 << (32 - prefix)) ))
                            else
                                total_ips=$(( total_ips + 1 ))
                            fi
                            ;;
                        * ) total_ips=$(( total_ips + 1 )) ;;
                    esac
                done < "${tmpfile}"

                # #
                #   Determine ASN and organization name
                #   
                #   Priority:
                #       › CLI-provided ASN arguments
                #       › Metadata embedded in the temp file
                #       › Filename fallback
                # #

                # #
                #   Only execute if argFolder + argFile + argASN specified
                # #

                if [[ -n "${argFolder}" && -n "${argFile}" && "${#argASN[@]}" -gt 0 ]]; then
                    debug "    ℹ️  Getting ASN and Org from list"

                    # #
                    #   Build comma+space ASN list for header output
                    # #
    
                    debug "    ℹ️  Found ASNs ${argASN[@]}"
                    ipset_read_asn=$(IFS=', '; echo "${argASN[*]}")

                    # #
                    #   Read organization name from META_ORG tag if present
                    # #

                    meta_org=$(grep -m1 '^# META_ORG=' "${tmpfile}" | cut -d'=' -f2)
                    ipset_read_orgname="${meta_org:-${basename_tmp}}"

                    # #
                    #   Normalize org name for safe filenames
                    # #

                    ipset_read_orgname=$(echo "${ipset_orgname}" \
                        | tr '[:upper:]' '[:lower:]' \
                        | sed 's/[^a-z0-9]/_/g; s/_\+/_/g; s/_$//')

                    ipset_display_org=$(echo "${ipset_read_orgname}" \
                        | tr '_' ' ' \
                        | sed 's/\b\(.\)/\u\1/g')

                    debug "    ℹ️  Assigning ASN ${ipset_read_asn}"


                # #
                #   Custom --folder and --file not specified
                # #

                else
                    debug "    ℹ️  Getting ASN and Org from temp file"

                    # #
                    #   Default behavior: read ASN & ORG from temp file
                    # #

                    ipset_read_asn=$(grep -m1 '^# META_ASN=' "${tmpfile}" | cut -d'=' -f2)
                    ipset_read_orgname=$(grep -m1 '^# META_ORG=' "${tmpfile}" | cut -d'=' -f2 | sed 's/^"\(.*\)"$/\1/')

                fi

                # #
                #   Generate metadata for header
                # #

                templ_url="https://raw.githubusercontent.com/${app_repo}/${app_repo_branch}/${folder_target_storage}/${relative_subfolder}/${basename_tmp}.${ext_target_ipset}"
                templ_now=$(date -u)
                templ_uuid=$(uuidgen -m -N "${TEMPL_ID}" -n @url)

                # #
                #   Write ipset header and metadata block
                # #

                {
                    echo "# #"
                    echo "#   🧱 Firewall Blocklist - ${target_file}"
                    echo "#"
                    echo "#   @url            ${templ_url}"
                    echo "#   @source         MaxMind GeoLite2 ASN Database"
                    echo "#   @id             ${basename_tmp}"
                    echo "#   @uuid           ${templ_uuid}"
                    echo "#   @updated        ${templ_now}"
                    echo "#   @entries        ${total_ips} ips"
                    echo "#                   ${total_subnets} subnets"
                    echo "#                   ${total_lines} lines"
                    echo "#   @expires        ${templ_exp}"
                    echo "#   @category       ${templ_category}"
                    echo "#"
                    echo "#   All IP ranges registered to ASN ${ipset_read_asn} (${ipset_read_orgname})"
                    echo "#   Includes both IPv4 and IPv6 networks merged"
                    echo "# #"
                    echo
                } > "${target_file}"

                # #
                #   Append actual IP ranges + strip comments
                # #

                grep -vE '^[#;]' "${tmpfile}" >> "${target_file}"

                # #
                #   Aggressive mode
                #   Merge all IPs into a single raw list
                # #

                if [ "${argAggressive}" = "true" ]; then
                    mkdir -p "$(dirname "${aggressive_raw}")"
                    grep -vE '^[#;]' "${tmpfile}" >> "${aggressive_raw}"
                fi

                # #
                #   Cleanup temp file after successful processing
                # #

                rm -f "${tmpfile}"
                ok "    🚛 Moved ${bluel}${tmpfile}${greym} › ${bluel}${target_file}${greym}"
                label "       ${greyd}› IPs: ${total_ips} › Subnets: ${total_subnets} › Lines: ${total_lines}${greym}"
                
            done < <(find "${DIR}" -type f -name "*.${folder_target_ext_tmp}" -print0)
        fi
    done

    # #
    #   Finalize aggressive blocklist
    #   Deduplicate, recalculate metrics, and write final file
    # #

    if [ "${argAggressive}" = "true" ] && [ -s "${aggressive_raw}" ]; then
        aggressive_dir="${folder_target_storage}/${folder_target_aggressive}"
        mkdir -p "${aggressive_dir}"

        # #
        #   Remove duplicate IPs while preserving order
        # #

        dedup_file="${aggressive_raw}.dedup"
        awk '!seen[$0]++' "${aggressive_raw}" > "${dedup_file}"

        # #
        #   Recalculate totals for merged list
        # #

        total_lines=0
        total_subnets=0
        total_ips=0
        while IFS= read -r subnet || [ -n "${subnet}" ]; do
            [[ -z "${subnet}" ]] && continue
            case "${subnet}" in \#*|\;*) continue ;; esac
            total_lines=$(( total_lines + 1 ))
            total_subnets=$(( total_subnets + 1 ))
            case "${subnet}" in
                *:* ) total_ips=$(( total_ips + 1 )) ;; # IPv6 counts as 1
                */* )
                    prefix=${subnet##*/}
                    if [[ "${prefix}" =~ ^[0-9]+$ ]] && [ "${prefix}" -ge 0 ] && [ "${prefix}" -le 32 ]; then
                        total_ips=$(( total_ips + (1 << (32 - prefix)) ))
                    else
                        total_ips=$(( total_ips + 1 ))
                    fi
                    ;;
                * ) total_ips=$(( total_ips + 1 )) ;;
            esac
        done < "${dedup_file}"

        # #
        #   Write final aggressive ipset header
        # #

        templ_url="https://raw.githubusercontent.com/${app_repo}/${app_repo_branch}/${folder_target_storage}/${folder_target_aggressive}/${file_target_aggressive}.${ext_target_ipset}"
        templ_now=$(date -u)
        templ_uuid=$(uuidgen)
        {
            echo "# #"
            echo "#   🧱 Firewall Blocklist - ${aggressive_file}"
            echo "#"
            echo "#   @url            ${templ_url}"
            echo "#   @source         MaxMind GeoLite2 ASN Database"
            echo "#   @id             aggressive"
            echo "#   @uuid           ${templ_uuid}"
            echo "#   @updated        ${templ_now}"
            echo "#   @entries        ${total_ips} ips"
            echo "#                   ${total_subnets} subnets"
            echo "#                   ${total_lines} lines"
            echo "#   @expires        ${templ_exp}"
            echo "#   @category       ${templ_category}"
            echo "#"
            echo "#   This blocklist contains IP ranges belonging to nearly every major VPS and hosting provider."
            echo "#   These networks are frequently used to deploy brute-force tools, scanning utilities, proxy"
            echo "#   relays, port sniffers, and many other forms of malicious traffic against exposed servers."
            echo "#   "
            echo "#   Providers such as Microsoft, Google, Amazon AWS, Azure, Hetzner, Contabo, HostGator,"
            echo "#   InMotion, OVH, DigitalOcean, Linode, and many others will be completely restricted here."
            echo "#   "
            echo "#   Use this blocklist only if you are certain that you want to block nearly all cloud or"
            echo "#   VPS infrastructure providers from reaching your server or hosted applications directly."
            echo "#   "
            echo "#   Includes all IPv4 and IPv6 networks merged"
            echo "# #"
            echo
        } > "${aggressive_file}"

        # Append deduplicated IPs
        grep -vE '^[#;]' "${dedup_file}" >> "${aggressive_file}"

        rm -f "${aggressive_raw}" "${dedup_file}"
        if [ ! -d "${aggressive_raw}" ]; then
            ok "    🗑️  Removed folder ${greenl}${aggressive_raw}"
        else
            error "    ❌ Failed to remove folder ${redl}${aggressive_raw}"
        fi
        
        if [ ! -d "${dedup_file}" ]; then
            ok "    🗑️  Removed folder ${greenl}${dedup_file}"
        else
            error "    ❌ Failed to remove folder ${redl}${dedup_file}"
        fi

        ok "    🚛 Finalized ${greenl}${aggressive_file}"
        label "       ${greyd}› IPs: ${total_ips} › Subnets: ${total_subnets} › Lines: ${total_lines}${greym}"
    fi

}

# #
#   Cleanup Garbage
#   
#   Removes old ipv4 and ipv5 folders
# #

function gcc( )
{
    echo
    info "    🗑️  Starting ${bluel}GCC${greym} cleanup"

    # #
    #   Remove temp
    #       ./blocklists/asn/geolite2/ipv4
    # #

    if [ -d ${path_storage_ipv4} ]; then
        rm -rf "${path_storage_ipv4}"
        if [ ! -d "${path_storage_ipv4}" ]; then
            ok "    🗑️  Removed folder ${greenl}${path_storage_ipv4}"
        else
            error "    ❌ Failed to remove folder ${redl}${path_storage_ipv4}"
        fi
    fi

    # #
    #   Remove temp
    #       ./blocklists/asn/geolite2/ipv6
    # #

    if [ -d ${path_storage_ipv6} ]; then
        rm -rf ${path_storage_ipv6}
        if [ ! -d "${path_storage_ipv6}" ]; then
            ok "    🗑️  Removed folder ${greenl}${path_storage_ipv6}"
        else
            error "    ❌ Failed to remove folder ${redl}${path_storage_ipv6}"
        fi
    fi

    # #
    #   Remove temp
    #       .github/temp
    # #

    rm -rf "${app_dir_github}/${folder_source_temp}"
    if [ ! -d "${app_dir_github}/${folder_source_temp}" ]; then
        ok "    🗑️  Removed folder ${greenl}${app_dir_github}/${folder_source_temp}"
    else
        error "    ❌ Failed to remove folder ${redl}${app_dir_github}/${folder_source_temp}"
    fi

}

# #
#   Main Function
#   
#   Accepts -p (parameters)
#       ./script -p LICENSE_KEY
# #

main()
{
    # #
    #   Start
    # #

    echo
    echo
    info "    ⭐ Starting ${bluel}${app_file_this}"

    # #
    #   Get license key
    #       ./aetherx.conf
    # #

    if [ -f "${app_dir_this_dir}/${file_cfg}" ]; then

        info "    📄 Loading config ${bluel}${app_dir_this_dir}/${file_cfg}"
        # shellcheck disable=SC1090
        . "${app_dir_this_dir}/${file_cfg}" >/dev/null 2>&1
    fi

    if [ -z "${argUseLocalDB}" ] && [ -z "${argMMLicense}" ]; then
        error "    ❌ Must supply valid MaxMind license key. Aborting ..."
    fi

    # #
    #   Check Packages
    #   
    #   Ensure all the packages we need are installed on the system.
    # #

    required_Packages

    # #
    #   Temp Path
    #   
    #   Local Mode          .github/local
    #   Network Mode        .github/.temp
    # #

    if [ "${argUseLocalDB}" = "false" ]; then
        mkdir -p "${app_dir_github}/${folder_source_temp}"
        if [ -d "${app_dir_github}/${folder_source_temp}" ]; then
            ok "    📂 Created ${greenl}${app_dir_github}/${folder_source_temp}"
        else
            error "    ❌ Failed to create ${redl}${app_dir_github}/${folder_source_temp}"
        fi

        TEMPDIR="${app_dir_github}/${folder_source_temp}"
    else
        mkdir -p "${app_dir_github}/${folder_source_local}"
        if [ -d "${app_dir_github}/${folder_source_local}" ]; then
            ok "    📂 Created ${greenl}${app_dir_github}/${folder_source_local}"
        else
            error "    ❌ Failed to create ${redl}${app_dir_github}/${folder_source_local}"
        fi

        TEMPDIR="${app_dir_github}/${folder_source_local}"
    fi

    ok "    📄 Set TEMPDIR ${greenl}${TEMPDIR}"
    export TEMPDIR

    # #
    #   Place geolite data in temporary directory
    # #

    info "    ⚙️  Creating tempdir folder ${bluel}${TEMPDIR}"
    OLD_PWD=$(pwd)
    cd "${TEMPDIR}" || exit 1

    # #
    #   Download / Unzip .zip
    # #

    maxmind_Database_Download
    maxmind_Database_Load

    # #
    #   Place set output in current working directory
    # #

    cd "$OLD_PWD" || exit 1

    # #
    #   Cleanup old files
    # #

    if [ "$argClean" = true ]; then

        info "    🗑️ Cleaning ${bluel}${folder_target_storage}"
        rm -rf "${folder_target_storage}"/*
        if [ ! -d "${folder_target_storage}" ]; then
            ok "    🗑️  Removed folder ${greenl}${folder_target_storage}"
        else
            error "    ❌ Failed to remove folder ${redl}${folder_target_storage}"
        fi

    fi

    # #
    #   Cleanup > ipv4
    # #

    rm -rf "${path_storage_ipv4}"
    if [ ! -d "${path_storage_ipv4}" ]; then
        ok "    🗑️  Removed folder ${greenl}${path_storage_ipv4}"
    else
        error "    ❌ Failed to remove folder ${redl}${path_storage_ipv4}"
    fi
    
    if [ ! -d "${path_storage_ipv4}" ]; then
        mkdir -p "${path_storage_ipv4}"

        if [ -d "${path_storage_ipv4}" ]; then
            ok "    📂 Created ${greenl}${path_storage_ipv4}"
        else
            error "    ❌ Failed to create ${redl}${path_storage_ipv4}"
        fi
    fi

    # #
    #   Cleanup > ipv6
    # #

    rm -rf "${path_storage_ipv6}"
    if [ ! -d "${path_storage_ipv6}" ]; then
        ok "    🗑️  Removed folder ${greenl}${path_storage_ipv6}"
    else
        error "    ❌ Failed to remove folder ${redl}${path_storage_ipv6}"
    fi

    if [ ! -d "${path_storage_ipv6}" ]; then
        mkdir -p "${path_storage_ipv6}"

        if [ -d "${path_storage_ipv6}" ]; then
            ok "    📂 Created ${greenl}${path_storage_ipv6}"
        else
            error "    ❌ Failed to create ${redl}${path_storage_ipv6}"
        fi
    fi

    # #
    #   Run actions
    # #

    generate_IPv4
    generate_IPv6
    ipsets_Merge
    ipsets_Finalize
    gcc
}

main "$@"