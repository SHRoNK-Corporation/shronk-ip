using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace shronkip.Controllers
{

    [ApiController]
    [Route("raw")]
    public class RawIPAPI : ControllerBase
    {
        private readonly ILogger<RawIPAPI> _logger;

        public RawIPAPI(ILogger<RawIPAPI> logger)
        {
            _logger = logger;
        }

        [HttpGet(Name = "GetRawIP")]
        public string Get()
        {
            IHeaderDictionary headers = HttpContext.Request.Headers;

            IPLookup client = Tool.GetIPHeaders(headers, HttpContext);

            return client.IP;
        }
    }
}