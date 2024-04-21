using Microsoft.AspNetCore.Mvc;

namespace shronkip.Controllers
{
    [ApiController]
    [Route("lookup")]
    public class LookupAPI : ControllerBase
    {

        private readonly ILogger<LookupAPI> _logger;

        public LookupAPI(ILogger<LookupAPI> logger)
        {
            _logger = logger;
        }

        [HttpGet(Name = "lookup")]
        public IPResult Get(string ip)
        {
            IHeaderDictionary headers = HttpContext.Request.Headers;
            IPLookup SourceIP = Tool.GetIPHeaders(headers, HttpContext);

            IPLookup client = new IPLookup
            {
                IP = ip,
                Source = "Lookup"
            };
            
            IPResult result = Tool.DbLookup(client, _logger);

            return result;
        }
    }

}
