using Microsoft.AspNetCore.Mvc;

namespace shronkip.Controllers
{
    [ApiController]
    [Route("imfeelinglucky")]
    public class LuckyAPI : ControllerBase
    {

        private readonly ILogger<LuckyAPI> _logger;

        public LuckyAPI(ILogger<LuckyAPI> logger)
        {
            _logger = logger;
        }

        [HttpGet(Name = "ImFeelingLucky")]
        public IPResult Get()
        {
            IHeaderDictionary headers = HttpContext.Request.Headers;

            IPLookup client = Tool.GetIPHeaders(headers, HttpContext);

            return Tool.LuckyLookup(client, _logger, 190);
        }
    }

}
