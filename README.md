# pkcs11-iot
A C sample program for establishing TLS connections, with a PKCS#11 library handling private key operations.

# Instructions

## Install dependencies
```sh
INSTALL_PATH=<install-path>

git clone https://github.com/awslabs/aws-lc.git
cmake -S aws-lc -B aws-lc/build -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH
cmake --build aws-lc/build --target install --parallel

git clone https://github.com/aws/s2n-tls.git
cmake -S s2n-tls -B s2n-tls/build -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DCMAKE_PREFIX_PATH=$INSTALL_PATH
cmake --build s2n-tls/build --target install --parallel

git clone https://github.com/awslabs/aws-c-common.git
cmake -S aws-c-common -B aws-c-common/build -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH
cmake --build aws-c-common/build --target install --parallel

git clone https://github.com/awslabs/aws-c-cal.git
cmake -S aws-c-cal -B aws-c-cal/build -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DCMAKE_PREFIX_PATH=$INSTALL_PATH
cmake --build aws-c-cal/build --target install --parallel

git clone -b pkcs11 https://github.com/awslabs/aws-c-io.git
cmake -S aws-c-io -B aws-c-io/build -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DCMAKE_PREFIX_PATH=$INSTALL_PATH
cmake --build aws-c-io/build --target install --parallel
```

## Build sample app
```sh
git clone https://github.com/graebm/pkcs11-iot.git
cmake -S pkcs11-iot -B pkcs11-iot/build -DCMAKE_PREFIX_PATH=$INSTALL_PATH
cmake --build pkcs11-iot/build
```

## Create IoT Thing
- In the AWS Console, navigate to [IoT Core](https://console.aws.amazon.com/iot/home)
- Manage -> Things -> Create things
- Step through wizard and ultimately download your new thing's: certificate, private key, and a Root CA
- Convert the private key into PKCS#8 format
  - `openssl pkcs8 -topk8 -in <private.pem.key> -out <private.p8.key> -nocrypt`

## Set up a SoftHSM token with the IoT key on it
1)  Install [SoftHSM2](https://www.opendnssec.org/softhsm/):
    ```
    > apt install softhsm
    ```

    Check that it's working:
    ```
    > softhsm2-util --show-slots
    ```

    If this spits out an error message, create a config file:
    *   Default location: `~/.config/softhsm2/softhsm2.conf`
    *   This file must specify token dir, default value is:
        ```
        directories.tokendir = /usr/local/var/lib/softhsm/tokens/
        ```

2)  Create token and import private key.

    You can use any values for the labels and PINs
    ```
    > softhsm2-util --init-token --free --label <token-label> --pin <user-pin> --so-pin <so-pin>
    ```

    Note which slot the token ended up in.

    ```
    > softhsm2-util --import tests/resources/unittests.p8 --slot <slot-with-token> --label <key-label> --id <hex-chars> --pin <user-pin>
    ```


## Run the test
-   Set the following env vars (you can omit most of these, just to see what happens when they're not specified):
    -   ENDPOINT: path like "xxxxxxxxxxxxxx-ats.iot.us-east-1.amazonaws.com". Find this in IoT Console -> Settings -> Device data endpoint
    -   PORT: 8883 is for direct MQTT connections using mTLS
    -   PKCS11_LIB_PATH: path to libsofthsm2.so
    -   PKCS11_USER_PIN: pin used while setting up token
    -   PKCS11_TOKEN_LABEL: label used while setting up token
    -   PKCS11_KEY_LABEL: label used while setting up token
    -   CERT_FILE: path to certificate.pem.crt
    -   ROOT_CA: path to AmazonRootCA1.pem

-   Run:
    ```
    > ./pkcs11-iot/buid/pkcs11-iot
    ```
