using System;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;


namespace Zephyr.Directory.Ldap
{
    public class LdapConfig
    {
        [JsonProperty(PropertyName = "server", NullValueHandling = NullValueHandling.Ignore)]
        public string Server { get; set; } = "localhost";

        [JsonProperty(PropertyName = "port", NullValueHandling = NullValueHandling.Ignore)]
        public int Port { get; set; } = 389;

        [JsonProperty(PropertyName = "ssl", NullValueHandling = NullValueHandling.Ignore)]
        public bool UseSSL { get; set; } = false;

        [JsonProperty(PropertyName = "username", NullValueHandling = NullValueHandling.Ignore)]
        public string Username { get; set; }

        [JsonProperty(PropertyName = "password", NullValueHandling = NullValueHandling.Ignore)]
        public string Password { get; set; }
    }
}
