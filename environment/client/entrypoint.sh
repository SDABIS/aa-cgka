#!/bin/bash

# Obtener el valor de INSTANCE_NAME desde la variable de entorno
INDEX=$(echo ${HOSTNAME##*-})
INSTANCE_NAME="User_${INDEX}"
export RUST_LOG="info"
export RUST_BACKTRACE=1
# Ejecutar el programa principal pasando INSTANCE_NAME como argumento
./simulated_client -n "$INSTANCE_NAME" -c "./Settings.toml"