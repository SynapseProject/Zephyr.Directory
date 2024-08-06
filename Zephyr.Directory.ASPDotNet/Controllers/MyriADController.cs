using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
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
            if (Request.Query.ContainsKey("maxResults"))
                request.MaxResults = Int32.Parse(Request.Query["maxResults"]);
            if (Request.Query.ContainsKey("nextToken"))
                request.NextToken = Request.Query["nextToken"];
            if (Request.Query.ContainsKey("attr"))
            {
                request.Attributes = new List<string>();
                foreach (string attr in Request.Query["attr"])
                    request.Attributes.Add(attr);
            }

            return Search(request);
        }

        [HttpPost]
        [Route("/search")]
        public LdapResponse Search(LdapRequest request)
        {
            Console.WriteLine(JsonTools.Serialize(request, true));

            LdapResponse response = request.Process();

            Console.WriteLine(JsonTools.Serialize(response, true));

            return response;
        }

    }
}

