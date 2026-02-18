#!/bin/bash

PASSPHRASE="this_is_sooo_secure_idgaf"
ALGO="aes-256-cbc"

usage() {
    echo "Usage: $0 [-e <dir>] [-d <dir>] [-g <dir> <num>]"
    echo "  -e <dir>      Encrypt files in directory"
    echo "  -d <dir>      Decrypt files in directory"
    echo "  -g <dir> <n>  Generate <n> files in directory"
    exit 1
}

generate_files() {
    local target_dir=$1
    local count=$2

    if [ ! -d "$target_dir" ]; then
        echo "'$target_dir' doesn't exist, created it right now."
        mkdir "$target_dir"
    fi
    
    echo "Generating $count files in $target_dir"
    for ((i=1; i<=count; i++)); do
        echo "Yeeeheee this is test file $i !!!" > "$target_dir/file_$i.txt"
    done
}

encryption() {
    local target_dir=$1
    echo "---- encrypting files in $target_dir ----"

    for file in "$target_dir"/*; do
        if [ -f "$file" ] && [[ "$file" != *.enc ]]; then
            openssl enc -$ALGO -pbkdf2 -iter 100000 -salt -in "$file" -out "$file.enc" -pass pass:$PASSPHRASE
            rm "$file"
            echo "encr & removed : $file"
        fi
    done
}

decryption() {
    local target_dir=$1
    echo "---- decrypting files in $target_dir ----"

    for file in "$target_dir"/*.enc; do
        if [ -f "$file" ]; then
            original_name="${file%.enc}"

            openssl enc -$ALGO -d -pbkdf2 -iter 100000 -in "$file" -out "$original_name" -pass pass:$PASSPHRASE
            rm "$file"
            echo "decrypted : $file"
        fi
    done
}

if [ $# -lt 2 ]; then
    usage
fi

case "$1" in
    -g)
        if [ $# -ne 3 ]; then usage; fi
        generate_files "$2" "$3"
        ;;
    -e)
        encryption "$2"
        ;;
    -d)
        decryption "$2"
        ;;
    *)
        usage
        ;;
esac
