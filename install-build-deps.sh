#!/bin/bash

echo "Downloading dotnet-install script"
wget https://dot.net/v1/dotnet-install.sh -O /tmp/dotnet-install.sh

echo "Installing .NET 8"
bash /tmp/dotnet-install.sh --channel 8.0
