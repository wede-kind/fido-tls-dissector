# Wireshark-Plugin to dissect the FIDO2 TLS 1.3 Extension

## FIDO2 TLS 1.3 Extension

This Wireshark plugin can be used to dissect the extension data of the FIDO2 TLS 1.3 Extension. The version of the extension this dissector is created for can be found under https://github.com/wede-kind/fidoSSL.

## Prerequisites

* a Wireshark Installation that supports any Lua version from 5.1 to 5.4

## Installation

You can use the plugin without installing any further dependencies by placing the file "FIDO2_TLS_dissector.lua" together with the file "cbor.lua" from the [lua-cbor Repository](https://github.com/Zash/lua-cbor) in the plugin directory of your Wireshark.
On Unix-like systems the standard location is _~/.local/lib/wireshark/plugins_.

## Usage

When inspecting a package in Wireshark that contains the FIDO extension, you can now find an additional entry called "FIDO Data" in the inspectation tab. You can find all data of the FIDO-extension dissected there.

You can easily filter for packages that contain the FIDO-extension in Wireshark by putting __tls.handshake.extension.type == 4660__ into the filter field.

Captures for testing purposes can be found in the _example_captures_ folder of this repository.
