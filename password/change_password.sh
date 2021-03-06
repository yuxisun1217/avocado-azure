#!/bin/bash
REALPATH=$(cd `dirname $0`; pwd)
PASSWORD_ENCRYPT="$REALPATH/password_encrypt"
PASSWORD_DECRYPT="$REALPATH/password.yaml"
cd $REALPATH

function help {
    echo ""
    echo "-a: Set Azure password"
    echo "-r: Set RHN password"
    echo "-p: The key password for encrypt/decrypt"
    echo "-d: Decrypt only"
}

function _set_pw {
    sed -i '/'"$1"'/{n;n;s/\(.*password: \)\(.*\)/\1'"$2"'/}' $PASSWORD_DECRYPT
}

function set_azure_pw {
    _set_pw AzureSub ${azure_pw}
    echo "Azure password changed."
    git commit $PASSWORD_ENCRYPT -m "Update Azure password"
}

function set_redhat_pw {
    _set_pw RedhatSub ${redhat_pw}
    echo "Redhat password changed."
    git commit $PASSWORD_ENCRYPT -m "Update RHN password"
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
while getopts "a:r:p:d" arg
do
    case $arg in
        a)
            azure_pw=$OPTARG;;
        r)
            redhat_pw=$OPTARG;;
        p)
            key_pw=$OPTARG;;
        d)
            decrypt_only=true;;
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

if [ ! $decrypt_only ];then
    if [ ! $azure_pw ] && [ ! $redhat_pw ];then
        echo "ERROR: Must set Azure or RHN password!"
        help
        exit 1
    fi
fi

# Decrypt
decrypt

if [ $decrypt_only ];then
    cat $PASSWORD_DECRYPT
    rm -f $PASSWORD_ENCRYPT
    exit 0
fi

# Modify password
if [ $azure_pw ];then
    set_azure_pw
fi
if [ $redhat_pw ];then
    set_redhat_pw
fi

# Encrypt
encrypt

# Push
git push
