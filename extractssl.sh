#!/usr/bin/ksh
# invoke with
# ./kgrep -f regexps/all /usr/bin/openssl | ./extractssl.sh /usr/bin/openssl | less

while read offset size; do
    dd if=$1 bs=1 skip=$offset count=$size | {
        openssl rsa -text -inform DER
    }
done
