﻿using Microsoft.AspNetCore.Mvc;

namespace shronkip.Controllers
{

    [ApiController]
    [Route("info")]
    public class InfoAPI : ControllerBase
    {
        private readonly ILogger<InfoAPI> _logger;

        public InfoAPI(ILogger<InfoAPI> logger)
        {
            _logger = logger;
        }

        [HttpGet(Name = "info")]
        public InfoResp Get()
        {
            return new InfoResp
            {
                Server = "SHRoNK-IP Reference Server v3.0.1",
                Maintainer = "SHRoNK Corporation",
                PassID = 5806798826
            };
        }
    }
}