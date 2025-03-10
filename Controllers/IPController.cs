using Microsoft.AspNetCore.Mvc;

namespace shronkip.Controllers
{

    [ApiController]
    [Route("/")]
    public class IpAPI : ControllerBase
    {

        private readonly ILogger<IpAPI> _logger;

        public IpAPI(ILogger<IpAPI> logger)
        {
            _logger = logger;
        }

        [HttpGet(Name = "GetIPInfo")]
        public IPResult Get()
        {
            IHeaderDictionary headers = HttpContext.Request.Headers;

            IPLookup client = Tool.GetIPHeaders(headers, HttpContext);

            IPResult result = Tool.DbLookup(client, _logger);

            return result;
        }
    }

    [ApiController]
    [Route("full")]
    public class FullAPI : ControllerBase
    {

        private readonly ILogger<FullAPI> _logger;

        public FullAPI(ILogger<FullAPI> logger)
        {
            _logger = logger;
        }

        [HttpGet(Name = "GetFullIPInfo")]
        public IPResult Get()
        {
            IHeaderDictionary headers = HttpContext.Request.Headers;

            IPLookup client = Tool.GetIPHeaders(headers, HttpContext);

            IPResult result = Tool.FullDbLookup(client, _logger);

            return result;
        }
    }

}