
# ATM18 Demo: Revoke Certificates for User

![version 2018.01](https://img.shields.io/badge/Version-2018.01-brightgreen.svg "version 2018.01") [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![Aruba Security Group](https://img.shields.io/badge/Source-Aruba_Security-orange.svg "Aruba Security Group")


## Overview
This is a _sample_ Python script to demonstrate using the ClearPass REST API to revoke all active certificates for a user.

__NOTE:__ This is a sample script from an Atmosphere 2018 Las Vegas session and is __not maintained or updated__.

## Released Version
2018.01 (2018-04-25)

## Dependencies
* Python 3
* Modules: `requests, json, os, configparser, sys`


## Pre-requisites
* An API client must be defined in ClearPass Guest under Administration » API Services » API Clients
* For password grants, an authentication service must be created in ClearPass Policy Manager to handle the OAuth 2.0 request

## Usage
Configure the required parameters in config/params.cfg:
* clearpass_fqdn
* grant_type

The remaining parameters vary by grant type.

> `revoke_certs.py  <username>`

## License
Copyright (c) Hewlett Packard Enterprise Development LP. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License").

## Other Information
Author: @timcappalli, Aruba Security Group

Organization: Aruba, a Hewlett Packard Enterprise company
