using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Zephyr.Crypto;
using Zephyr.Directory.Ldap;

namespace Zephyr.Directory.ASPDotNet.Controllers
{
    [ApiController]
    [Route("/")]
    public class MyriADController : ControllerBase
    {
        private readonly ILogger<MyriADController> _logger;

        public MyriADController(ILogger<MyriADController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        [Route("/{objectType}/{*value}")]
        public LdapResponse Get(string objectType, string value)
        {
            LdapRequest request = new LdapRequest();

            request.ObjectType = Enum.Parse<ObjectType>(objectType, true);
            request.SearchValue = value;
            if (Request.Query.ContainsKey("domain"))
                request.Domain = Request.Query["domain"];
            if (Request.Query.ContainsKey("searchBase"))
                request.SearchBase = Request.Query["searchBase"];
            if (Request.Query.ContainsKey("searchScope"))
                request.SearchScope = Enum.Parse<SearchScopeType>(Request.Query["searchScope"], true);

            // TODO : Add MaxResults, NextToken, Attributes and MaxPageSize

            Console.WriteLine(JsonTools.Serialize(request, true));
            return Search(request);
        }

        [HttpPost]
        [Route("/search")]
        public LdapResponse Search(LdapRequest request)
        {
            Console.WriteLine(JsonTools.Serialize(request, true));

            bool isPing = request.Ping.HasValue;

            LdapResponse response = new LdapResponse();

            if (request.Crypto?.Text != null)
            {
                LdapUtils.ApplyDefaulsAndValidate(request.Crypto);
                response.Message = Rijndael.Encrypt(request.Crypto.Text, request.Crypto.PassPhrase, request.Crypto.SaltValue, request.Crypto.InitVector);
            }
            else if (isPing)
            {
                System.Reflection.Assembly assembly = System.Reflection.Assembly.GetExecutingAssembly();
                System.Diagnostics.FileVersionInfo fvi = System.Diagnostics.FileVersionInfo.GetVersionInfo(assembly.Location);
                string version = fvi.FileVersion;

                response.Message = "Hello From MyriAD (" + version + ").";
                if (request.Ping == PingType.Echo)
                    Console.WriteLine("Ping");
            }
            else
            {
                try
                {
                    LdapUtils.ApplyDefaulsAndValidate(request);
                    string searchFilter = LdapUtils.GetSearchString(request);
                    LdapServer ldap = new LdapServer(request.Config);
                    ldap.Bind(request.Config);
                    if (request.Config.TokenType == "Server" || request.Config.TokenType == "Client")
                    {
                        response = ldap.Search(request, request.SearchBase, searchFilter, request.Attributes, request.SearchScope, request.MaxResults, request.NextToken, request.Union);

                    }
                    else
                    {
                        throw new FormatException("Warning: TokenType must be set to Server or Client");
                    }
                    ldap.Disconnect();
                }
                catch (Exception e)
                {
                    response = LdapServer.ReturnError(e, request.Config);
                }
            }
            Console.WriteLine(JsonTools.Serialize(response, true));

            return response;
        }

    }
}

