﻿using System;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;

using Zephyr.Crypto;


namespace Zephyr.Directory.Ldap
{
    public class Crypto
    {
        [JsonProperty(PropertyName = "iv", NullValueHandling = NullValueHandling.Ignore)]
        public string InitVector { get; set; }

        [JsonProperty(PropertyName = "salt", NullValueHandling = NullValueHandling.Ignore)]
        public string SaltValue { get; set; }

        [JsonProperty(PropertyName = "passphrase", NullValueHandling = NullValueHandling.Ignore)]
        public string PassPhrase { get; set; }

        // When Present, Return Encrypted Value
        [JsonProperty(PropertyName = "text", NullValueHandling = NullValueHandling.Ignore)]
        public string TextValue { get; set; }

    }
}
