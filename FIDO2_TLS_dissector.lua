local cbor = require"cbor";
--local cbor = require "org.conman.cbor" --if you change the used library, one line of code has to be replaced with a commented out one

local function hex(bytestring)
    return bytestring:gsub(":(%x%x)", function (x) return string.char(tonumber(x, 16)) end):gsub("%x%x", function (x) return string.char(tonumber(x, 16)) end, 1)
end

local function bytestohex(str)
    return (str:gsub(".", function(char) return string.format("%02x", char:byte()) end))
 end
 
local message_types = {"Pre Indication", "Pre Request", "Registration Indication", 
"Registration Request", "Registration Response", "Authentication Indication", 
"Authenticaation Request", "Authentication Response"}

-- https://www.iana.org/assignments/cose/cose.xhtml#algorithms
local public_key_algorithms = {}
    public_key_algorithms[-7] = "COSE_ES256"
    public_key_algorithms[-35] = "COSE_ES384"
    public_key_algorithms[-8] = "COSE_EDDSA"
    public_key_algorithms[-25] = "COSE_ECDH_ES256" --https://github.com/Yubico/libfido2/blob/main/src/es256.c Zeile 90
    public_key_algorithms[-257] = "COSE_RS256"
    public_key_algorithms[-65535] = "COSE_RS1"

local optionals_list = {"Timeout", "Authentication Selector", "Excluded Credentials", "Attestation", "Extensions"}

local attachment_list = {"PLATFORM", "CROSS-PLATFORM"}
local resident_key_list = {"REQUIRED", "PREFERRED", "DISCOURAGED"}
local user_verification_list = {"REQUIRED", "PREFERRED", "DISCOURAGED"}

tls_extension_type_f = Field.new("tls.handshake.extension.type")
tls_fido_extension_len_f = Field.new("tls.handshake.extension.len")
tls_fido_extension_data_f = Field.new("tls.handshake.extension.data")


fido_extension_proto = Proto("fido_extension_analyzer", "For analyzing FIDO in the TLS handshake")

fido_extension_len_F = ProtoField.string("extension.fido_len", "Length")
fido_extension_data_raw_F = ProtoField.string("extension.fido_data", "Raw")
fido_extension_data_message_type_F = ProtoField.string("extension.fido_data_message_type", "FIDO Message Type")
fido_message_type_F = ProtoField.string("extension.fido_message_type", "Message Type")
fido_ephemeral_user_id_F = ProtoField.string("extension.fido_ephemeral_user_id", "Ephemeral User ID")
fido_gcm_key_F = ProtoField.string("extension.fido_gcm_key", "GCM Key")
fido_user_name_F = ProtoField.string("extension.fido_user_name", "User Name")
fido_user_displayname_F = ProtoField.string("extension.fido_user_display_name", "User Display Name")
fido_ticket_F = ProtoField.string("extension.fido_ticket", "Ticket")
fido_challenge_F = ProtoField.string("extension.fido_challenge", "Challenge")
fido_rp_id_F = ProtoField.string("extension.fido_rp_id", "RP ID")
fido_rp_name_F = ProtoField.string("extension.fido_rp_name", "RP Name")
fido_encrypted_user_name_F = ProtoField.string("extension.encrypted_fido_user_name", "Encrypted User Name")
fido_encrypted_user_displayname_F = ProtoField.string("extension.encrypted_fido_user_display_name", "Encrypted User Display Name")
fido_encrypted_ticket_F = ProtoField.string("extension.encrypted_fido_ticket", "Encrypted ticket")
fido_user_id_F = ProtoField.string("extension.fido_user_id", "User ID")
fido_encrypted_user_id_F = ProtoField.string("extension.encrypted_user_id", "Encrypted User ID")
fido_public_key_algorithm_F = ProtoField.string("extension.public_key_algorithm", "Public Key Algorithm")
fido_timeout_F = ProtoField.string("extension.timeout", "Timeout")
fido_attachment_F = ProtoField.string("extension.attachment", "Attachment")
fido_resident_key_F = ProtoField.string("extension.resident_key", "Resident Key")
fido_user_verification_F = ProtoField.string("extension.user_verification_encrypted", "User Verification")

fido_credential_type_F = ProtoField.string("extension.fido_credential_type", "Credential Type")
fido_credential_id_F = ProtoField.string("extension.fido_credential_id", "Credential ID")
fido_transports_F = ProtoField.string("extension.transports", "Transports")

fido_extension_id_F = ProtoField.string("extension.extension_id", "Extension ID")
fido_extension_data_F = ProtoField.string("extension.extension_data", "Extension Data")

fido_attestation_object_F = ProtoField.string("extension.attestation_object", "Attestation Object")
fido_clientdata_json_F = ProtoField.string("extension.clientdata_json", "Clientdata JSON")

fido_authenticator_data_F = ProtoField.string("extension.authenticator_data", "Authenticator Data")
fido_signature_F = ProtoField.string("extension.signature", "Signature")
fido_user_handle_F = ProtoField.string("extension.user_handle", "User Handle")
fido_selected_credential_id_F = ProtoField.string("extension.selected_credential_id", "Selected Credential ID")


fido_extension_proto.fields = {fido_extension_len_F, fido_extension_data_raw_F, fido_extension_data_message_type_F, 
fido_message_type_F, fido_ephemeral_user_id_F, fido_gcm_key_F, fido_user_name_F, fido_user_displayname_F, fido_ticket_F, 
fido_challenge_F, fido_rp_id_F, fido_rp_name_F, fido_encrypted_user_name_F, fido_encrypted_user_displayname_F, 
fido_encrypted_ticket_F, fido_user_id_F, fido_encrypted_user_id_F, fido_public_key_algorithm_F, fido_timeout_F,fido_attachment_F, 
fido_resident_key_F, fido_user_verification_F,fido_credential_type_F, fido_credential_id_F, fido_extension_id_F, 
fido_extension_data_F, fido_attestation_object_F, fido_clientdata_json_F,fido_authenticator_data_F, fido_signature_F, 
fido_user_handle_F, fido_selected_credential_id_F}


function fido_extension_proto.dissector(buffer,pinfo,tree)
    local fields = { all_field_infos() }
    finfos_type = { tls_extension_type_f() }
    finfos_len = { tls_fido_extension_len_f() }
    finfos_data = { tls_fido_extension_data_f() }


    if #finfos_type > 0 then
        for ix, finfo_type in ipairs(finfos_type) do
            if tostring(finfo_type) == "4660" then
                print("start of packet")
                local subtree = tree:add(fido_extension_proto,"FIDO Data")
                local fido_extension_len = finfos_len[ix]
                local fido_extension_data = finfos_data[1]
                --local decoded_data = cbor.decode(hex(tostring(fido_extension_data))) --if org.conman.cbor is used as the CBOR library
                local decoded_data = cbor.decode(tostring(hex(tostring(fido_extension_data)))) --if LUA-CBOR is used as the CBOR library

                local fido_message_type = decoded_data[1]

                subtree:add(fido_message_type_F, message_types[fido_message_type])
                subtree:add(fido_extension_data_message_type_F, fido_message_type)
                subtree:add(fido_extension_len_F, tostring(fido_extension_len))
                subtree:add(fido_extension_data_raw_F, tostring(fido_extension_data.value):lower())
                
                -- PreIndication
                if fido_message_type == 1 then 
                    print("end of packet" .. fido_message_type)
                    --goto continue 
                end

                -- PreRequest
                if fido_message_type == 2 then
                    print(decoded_data[2])
                    subtree:add(fido_ephemeral_user_id_F, bytestohex(decoded_data[2]))
                    print(decoded_data[3])
                    subtree:add(fido_gcm_key_F, bytestohex(decoded_data[3]))
                    print("end of packet" .. fido_message_type)
                    --goto continue
                end

                -- Registration Indication
                if fido_message_type == 3 then
                    print(decoded_data[2])
                    subtree:add(fido_ephemeral_user_id_F, bytestohex(decoded_data[2]))
                    print(decoded_data[2])
                    subtree:add(fido_encrypted_user_name_F, bytestohex(decoded_data[3]))
                    print(decoded_data[3])
                    subtree:add(fido_encrypted_user_displayname_F, bytestohex(decoded_data[4]))
                    print(decoded_data[4])
                    subtree:add(fido_encrypted_ticket_F, bytestohex(decoded_data[5]))
                    print("end of packet" .. fido_message_type)
                    --goto continue
                end

                -- Registration Request
                if fido_message_type == 4 then 
                    print(decoded_data[2])
                    subtree:add(fido_challenge_F, bytestohex(decoded_data[2]))
                    print(decoded_data[3])
                    subtree:add(fido_rp_id_F, decoded_data[3])
                    print(decoded_data[4])
                    subtree:add(fido_rp_name_F, decoded_data[4])
                    print(decoded_data[5])
                    subtree:add(fido_encrypted_user_name_F, bytestohex(decoded_data[5]))
                    print(decoded_data[6])
                    subtree:add(fido_encrypted_user_displayname_F, bytestohex(decoded_data[6]))
                    print(decoded_data[7])
                    subtree:add(fido_encrypted_user_id_F, bytestohex(decoded_data[7]))
                    local pubkey_cred_params = decoded_data[8]
                    print(pubkey_cred_params)
                    local pubkey_tree = subtree:add("Pubkey Cred Params")
                    for k, pubkey_cred_param in pairs(pubkey_cred_params) do
                        pubkey_tree:add(fido_public_key_algorithm_F, public_key_algorithms[pubkey_cred_param])
                    end
                    local optionals = decoded_data[9]
                    print(optionals)
                    if next(optionals) ~= nil then
                        local optionals_tree = subtree:add("Optionals")
                        for k,v in pairs(optionals) do
                            print(k)
                            print(v)
                            if k == 1 then
                                optionals_tree:add(fido_timeout_F, v)
                            end
                            if k == 2 then
                                print(v[1])
                                print(v[2])
                                print(v[3])
                                local authenticator_selection_tree = optionals_tree:add("Authenticator Selection")
                                authenticator_selection_tree:add(fido_attachment_F, attachment_list[v[1]])
                                authenticator_selection_tree:add(fido_resident_key_F, resident_key_list[v[2]])
                                authenticator_selection_tree:add(fido_user_verification_F, user_verification_list[v[3]])
                            end
                            if k == 3 then
                                print(v[1])
                                print(v[2])
                                print(v[3])
                                print(v[4])
                                for k2,v2 in pairs(v) do
                                    if k2 % 2 == 1 then
                                        local excluded_credentials_tree = optionals_tree:add("Excluded Credentials")
                                        excluded_credentials_tree:add(fido_credential_type_F, v2)
                                        excluded_credentials_tree:add(fido_credential_id_F, bytestohex(v[k2+1]))
                                    end
                                end
                            end
                        end
                    end
                    print("endepaket" .. fido_message_type)
                    --goto continue
                end

                -- Registration Response
                if fido_message_type == 5 then
                    print(decoded_data[2])
                    subtree:add(fido_attestation_object_F, bytestohex(decoded_data[2]))
                    print(decoded_data[3])
                    subtree:add(fido_clientdata_json_F, decoded_data[3])
                    print("end of packet" .. fido_message_type)
                    --goto continue
                end

                --Authentication Indication (non-discoverable) is missing

                -- Authentication Indication (discoverable)
                if fido_message_type == 6 then --should be 7, but is changed to 6 in current implementation
                    print("end of packet" .. fido_message_type)
                    --goto continue 
                end

                -- Authentication Request
                if fido_message_type == 7 then --should be 8, but is changed to 7 in current implementation
                    print(decoded_data[2])
                    subtree:add(fido_challenge_F, bytestohex(decoded_data[2]))
                    local optionals = decoded_data[3]
                    print(optionals)
                    if next(optionals) ~= nil then
                        local optionals_tree = subtree:add("Optionals")
                        for k,v in pairs(optionals) do
                            print(k)
                            print(v)
                            if k == 1 then
                                optionals_tree:add(fido_timeout_F, v)
                            end
                            if k == 2 then
                                optionals_tree:add(fido_rp_id_F, v)
                            end
                            if k == 3 then
                                optionals_tree:add(fido_user_verification_F, user_verification_list[v])
                            end
                        end
                    end
                    print("end of packet" .. fido_message_type)
                    --goto continue
                end

                -- Authencication Response
                if fido_message_type == 8 then --should be 9, but is changed to 8 in current implementation
                    print(decoded_data[2])
                    subtree:add(fido_clientdata_json_F, decoded_data[2])
                    print(decoded_data[3])
                    subtree:add(fido_authenticator_data_F, bytestohex(decoded_data[3]))
                    print(decoded_data[4])
                    subtree:add(fido_signature_F, bytestohex(decoded_data[4]))
                    local optionals = decoded_data[5]
                    print(type(optionals))
                    print(optionals)
                    if next(optionals) ~= nil then 
                        local optionals_tree = subtree:add("Optionals")
                        for k,v in pairs(optionals) do
                            print(k)
                            print(v)
                            if k == 1 then
                                optionals_tree:add(fido_user_handle_F, bytestohex(v))
                            end
                            if k == 2 then
                                optionals_tree:add(fido_selected_credential_id_F, bytestohex(v))
                            end
                        end
                    end
                    print("end of packet" .. fido_message_type)
                end
            end
        end
        --::continue::
    end
end

register_postdissector(fido_extension_proto)