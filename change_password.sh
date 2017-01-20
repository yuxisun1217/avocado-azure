#!/bin/bash
PASSWORD_ENCRYPT="password_encrypt"
PASSWORD_DECRYPT="password.yaml"

function help {
    echo ""
    echo "-a: Set Azure password"
    echo "-r: Set RHN password"
    echo "-p: The key password for encrypt/decrypt"
}

function _set_pw {
    sed -i '/'"$1"'/{n;n;s/\(.*password: \)\(.*\)/\1'"$2"'/}' $PASSWORD_DECRYPT
}

function set_azure_pw {
    _set_pw AzureSub ${azure_pw}
    echo "Azure password changed."
}

function set_redhat_pw {
    _set_pw RedhatSub ${redhat_pw}
    echo "Redhat password changed."
}

function decrypt {
    git checkout $PASSWORD_ENCRYPT
    rm -f $PASSWORD_DECRYPT
    openssl enc -des3 -d -in $PASSWORD_ENCRYPT -out $PASSWORD_DECRYPT -k $key_pw
    grep "AzureSub" $PASSWORD_DECRYPT > /dev/null
    if [ $? -eq 0 ]; then
        echo "Decrypt to $PASSWORD_DECRYPT successfully."
    else
        echo "Fail to decrypt to $PASSWORD_DECRYPT."
        exit 1
    fi
}

function encrypt {
    rm -f $PASSWORD_ENCRYPT
    openssl enc -des3 -e -in $PASSWORD_DECRYPT -out $PASSWORD_ENCRYPT -k $key_pw
    echo "Encrypt to $PASSWORD_ENCRYPT successfully."
}

# Parse options
while getopts "a:r:p:" arg
do
    case $arg in
        a)
            azure_pw=$OPTARG;;
        r)
            redhat_pw=$OPTARG;;
        p)
            key_pw=$OPTARG;;
        ?)  # else
            help
        exit 1
    esac
done

if [ ! $key_pw ];then
    echo "ERROR: Must input encrypt password!"
    help
    exit 1
fi

if [ ! $azure_pw ] && [ ! $redhat_pw ];then
    echo "ERROR: Must set Azure or RHN password!"
    help
    exit 1
fi

# Decrypt
decrypt

# Modify password
if [ $azure_pw ];then
    set_azure_pw
fi
if [ $redhat_pw ];then
    set_redhat_pw
fi

# Encrypt
encrypt
