#!/bin/bash

DOTNET_ROOT=${HOME}/.dotnet
PATH=${DOTNET_ROOT}:${PATH}

bash ./install-build-deps.sh

dotnet --info
dotnet build
