"use strict";


/********* External Imports ********/

var lib = require("./lib");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setup_cipher = lib.setup_cipher,
    enc_gcm = lib.enc_gcm,
    dec_gcm = lib.dec_gcm,
    bitarray_slice = lib.bitarray_slice,
    bitarray_to_string = lib.bitarray_to_string,
    string_to_bitarray = lib.string_to_bitarray,
    bitarray_to_hex = lib.bitarray_to_hex,
    hex_to_bitarray = lib.hex_to_bitarray,
    bitarray_to_base64 = lib.bitarray_to_base64,
    base64_to_bitarray = lib.base64_to_bitarray,
    byte_array_to_hex = lib.byte_array_to_hex,
    hex_to_byte_array = lib.hex_to_byte_array,
    string_to_padded_byte_array = lib.string_to_padded_byte_array,
    string_to_padded_bitarray = lib.string_to_padded_bitarray,
    string_from_padded_byte_array = lib.string_from_padded_byte_array,
    string_from_padded_bitarray = lib.string_from_padded_bitarray,
    random_bitarray = lib.random_bitarray,
    bitarray_equal = lib.bitarray_equal,
    bitarray_len = lib.bitarray_len,
    bitarray_concat = lib.bitarray_concat,
    dict_num_keys = lib.dict_num_keys;


/********* Implementation ********/


var keychain = function() {
  // Class-private instance variables.
  var priv = {
    secrets: { /* Your secrets here */ },
    data: { /* Non-secret data here */ }
  };

  // Maximum length of each record in bytes
  var MAX_PW_LEN_BYTES = 64;
  
  var ready = false;

  var keychain = {};  

  priv.data.hmacGen = random_bitarray(32);
  priv.data.gcmGen = random_bitarray(32);
  priv.data.authenticationGen = random_bitarray(32);
  /** 
    * Creates an empty keychain with the given password. Once init is called,
    * the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  keychain.init = function(password) {
    if(ready) ready = false;

    // Definindo o salt
    priv.secrets.salt = random_bitarray(128);
    // Gerando uma chave mestra para o programa
    priv.secrets.masterKey = KDF(password, priv.secrets.salt);
    // Gerando a uma key HMAC, GCM e para autenticação
    priv.secrets.hmacKey = HMAC(priv.secrets.masterKey, priv.data.hmacGen);
    priv.secrets.gcmKey = HMAC(priv.secrets.masterKey, priv.data.gcmGen);
    priv.data.authenticationKey = HMAC(priv.secrets.masterKey, priv.data.authenticationGen);
    
    ready = true;
  };

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the save function). The trusted_data_check
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (e.g., the result of a 
    * call to the save function). Returns true if the data is successfully loaded
    * and the provided password is correct. Returns false otherwise.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trusted_data_check: string
    * Return Type: boolean
    */
  keychain.load = function(password, repr, trusted_data_check) {
    ready = false;
    var reprSHA256 = string_to_bitarray(SHA256(string_to_bitarray(repr)));
    var tdcBitArray = string_to_bitarray(trusted_data_check);

    if(!bitarray_equal(reprSHA256, tdcBitArray)) {
      throw "Ops! Algo deu errado =/";
    }

    var reprParsed = JSON.parse(repr);

    var auxSalt = reprParsed["Salt"];
    var auxKeychain = reprParsed["Keychain"];

    var auxKDF = KDF(password, auxSalt);
    var auxAuth = HMAC(auxKDF, reprParsed.authenticationGen);

    if(!bitarray_equal(auxAuth, reprParsed.authenticationKey)) {
      return false;
    }

    priv.data = reprParsed;
    keychain = JSON.parse(auxKeychain);
    priv.secrets.salt = auxSalt;

    priv.secrets.masterKey = KDF(password, priv.secrets.salt);
    priv.secrets.hmacKey = HMAC(priv.secrets.masterKey, priv.data.hmacGen);
    priv.secrets.gcmKey = HMAC(priv.secrets.masterKey, priv.data.gcmGen);
    priv.data.authenticationKey = auxAuth;


    delete reprParsed["Salt"];
    delete reprParsed["Keychain"];
    ready = true;
    return true;
    };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */ 
  keychain.dump = function() {
    if(!ready) return null;

    var auxDump = JSON.parse(JSON.stringify(priv.data));

    var auxKeychain = JSON.stringify(keychain);
    auxDump["Salt"] = priv.secrets.salt;
    auxDump["Keychain"] = auxKeychain;

    var dump = JSON.stringify(auxDump);
    return [dump, SHA256(string_to_bitarray(dump))];
  }

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: string
    */
  keychain.get = function(name) {
    if(!ready) throw "Keychain não inicializado.";

    var auxHMAC = HMAC(priv.secrets.hmacKey, name);
    // Se não existir uma chave auxHMAC no data, retorne null
    var cifrotexto = keychain[auxHMAC];
    if(!cifrotexto) return null;

    // Gerando GCM para decriptação do cifrotexto
    var auxGCM = setup_cipher(bitarray_slice(priv.secrets.gcmKey, 0, 128));

    // Recuperando puro texto a partir do cifrotexto obtido pelo name
    var purotexto = dec_gcm(auxGCM, cifrotexto);

    // Calculando o HMAC do purotexto para comparação com o HMAC obtido
    var puroHMAC = bitarray_slice(purotexto, bitarray_len(purotexto)-bitarray_len(auxHMAC), bitarray_len(purotexto));
   
    if(!bitarray_equal(auxHMAC, puroHMAC)) {
      throw "Ops! Algo deu errado =/";
    }

    var puroPassword = bitarray_slice(purotexto, 0, bitarray_len(purotexto) - bitarray_len(auxHMAC));
    var paddedPassword = string_from_padded_bitarray(puroPassword, MAX_PW_LEN_BYTES);

    return paddedPassword;
  }

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  keychain.set = function(name, value) {
    if(!ready) throw "Keychain não inicializado.";

    var auxHMAC = HMAC(priv.secrets.hmacKey, name);

    var paddedPassword = string_to_padded_bitarray(value, MAX_PW_LEN_BYTES);

    var auxGCM = setup_cipher(bitarray_slice(priv.secrets.gcmKey, 0, 128));

    var ciphertext = enc_gcm(auxGCM, bitarray_concat(paddedPassword, auxHMAC));
    keychain[auxHMAC] = ciphertext;
  }

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: boolean
  */
  keychain.remove = function(name) {
    if(!ready) throw "Keychain não inicializado.";

    var auxHMAC = HMAC(priv.secrets.hmacKey, name);

    if(!keychain[auxHMAC]) {
      return false;
    } else {
      delete keychain[auxHMAC];
      return true;
    }
  }

  return keychain;
}

module.exports.keychain = keychain;
