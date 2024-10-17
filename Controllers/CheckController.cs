using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;

namespace shronkip.Controllers
{

    [ApiController]
    [Route("check/api/auth")]
    public class CheckAuthAPI : ControllerBase
    {
        private readonly ILogger<CheckAuthAPI> _logger;
        private readonly AppDbContext _context;

        public CheckAuthAPI(ILogger<CheckAuthAPI> logger, AppDbContext context)
        {
            _logger = logger;
            _context = context;
        }

        [HttpGet(Name = "CheckAuthAPI")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(CorsResp))]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public IActionResult Get(string URL)
        {
            Uri uriResult;
            bool FirstURLValidation = Uri.TryCreate(URL, UriKind.Absolute, out uriResult)
                && (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps);

            if (FirstURLValidation)
            {
                string Pattern = @"^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$";
                Regex Rgx = new Regex(Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);
                if (!Rgx.IsMatch(URL) || URL.Contains("<script>") || URL.Contains("://192.168"))
                { return BadRequest(); }
            } else { return BadRequest(); }

            if (URL.EndsWith('/'))
            {
                URL = URL.Remove(startIndex: URL.Length - 1);
            }

            var audit = new Audit();

            IPLookup client = Tool.GetIPHeaders(HttpContext.Request.Headers, HttpContext);
            audit.OriginatingIP = client.IP;
            audit.OriginatingUA = HttpContext.Request.Headers.UserAgent;
            audit.URL = URL;
            _context.Add(audit);
            _context.SaveChanges();

            return Ok(new AuthResp
            {
                Token = audit.Token
            });
        }
    }

    [ApiController]
    [Route("check/api/token")]
    public class CheckTokenAPI : ControllerBase
    {
        private readonly ILogger<CheckTokenAPI> _logger;
        private readonly AppDbContext _context;

        public CheckTokenAPI(ILogger<CheckTokenAPI> logger, AppDbContext context)
        {
            _logger = logger;
            _context = context;
        }

        [HttpGet(Name = "CheckTokenAPI")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(Audit))]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public IActionResult Get(string Token)
        {
            var audit = _context.Audits.Where(u => u.Token == Token).FirstOrDefault();
            return audit == null ? BadRequest() : Ok(audit);
        }
    }

    [ApiController]
    [Route("check/api/cors")]
    public class CheckCorsAPI : ControllerBase
    {
        private readonly ILogger<CheckCorsAPI> _logger;
        private readonly AppDbContext _context;

        public CheckCorsAPI(ILogger<CheckCorsAPI> logger, AppDbContext context)
        {
            _logger = logger;
            _context = context;
        }

        [HttpGet(Name = "CheckCorsAPI")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(CorsResp))]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public IActionResult Get(string Token)
        {
            var audit = _context.Audits.Where(u => u.Token == Token).FirstOrDefault();

            if (audit == null || audit.CorsRan == true || audit.Finished == true) { return BadRequest(); }
            else
            {
                audit.CorsRan = true;
                _context.Update(audit);
                _context.SaveChanges();
                if (audit.OriginatingIP != Tool.GetIPHeaders(HttpContext.Request.Headers, HttpContext).IP
                    || audit.OriginatingUA != HttpContext.Request.Headers.UserAgent)
                {
                    return BadRequest();
                }
                else
                {
                    using HttpClient client = new HttpClient();
                    {
                        client.DefaultRequestHeaders.Add("Origin", "one's mother");
                        client.DefaultRequestHeaders.Add("Access-Control-Request-Method", "GET");

                        HttpResponseMessage response;
                        try { response = client.GetAsync(audit.URL).Result; }
                        catch
                        {
                            audit.Finished = true;
                            _context.Update(audit);
                            _context.SaveChanges();
                            return Ok(new CorsResp { ConnectPass = false, CorsPass = false, Message = "Could not connect" });
                        }

                        using HttpResponseMessage infoResponse = client.GetAsync(String.Concat(audit.URL, "/info")).Result;
                        try { infoResponse.EnsureSuccessStatusCode(); }
                        catch { }

                        InfoResp info = new InfoResp();

                        try { 
                            info = infoResponse.Content.ReadFromJsonAsync<InfoResp>().Result;
                            audit.Server = info.Server;
                        }
                        catch { }


                        try
                        { if (response.Headers.GetValues("Access-Control-Allow-Origin").First() == "*") {
                                audit.ConnectPass = true; audit.CorsPass = true;
                                _context.Update(audit);
                                _context.SaveChanges();
                                return Ok(new CorsResp { ConnectPass = true, CorsPass = true, Message = "" }); 
                            }
                            else {
                                audit.ConnectPass = true;
                                _context.Update(audit);
                                _context.SaveChanges();
                                return Ok(new CorsResp { ConnectPass = true, CorsPass = false, Message = "Cors denied" });
                            } 
                        }
                        catch {
                            audit.ConnectPass = true;
                            _context.Update(audit);
                            _context.SaveChanges();
                            return Ok(new CorsResp { ConnectPass = true, CorsPass = false, Message = "Cors header missing" }); 
                        }

                    }
                }
            }

        }
    }

    [ApiController]
    [Route("check/api/ip")]
    public class CheckIPAPI : ControllerBase
    {
        private readonly ILogger<CheckIPAPI> _logger;
        private readonly AppDbContext _context;

        public CheckIPAPI(ILogger<CheckIPAPI> logger, AppDbContext context)
        {
            _logger = logger;
            _context = context;
        }

        [HttpGet(Name = "CheckIPAPI")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(IPResp))]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public IActionResult Get(string Token)
        {
            var audit = _context.Audits.Where(u => u.Token == Token).FirstOrDefault();

            if (audit == null || audit.IPRan == true || audit.Finished == true || audit.CorsRan != true) { return BadRequest(); }
            else
            {
                audit.IPRan = true;
                _context.Update(audit);
                _context.SaveChanges();
                if (audit.OriginatingIP != Tool.GetIPHeaders(HttpContext.Request.Headers, HttpContext).IP
                    || audit.OriginatingUA != HttpContext.Request.Headers.UserAgent)
                {
                    return BadRequest();
                }
                else
                {
                    using HttpClient client = new HttpClient();
                    {
                        string RealIP = client.GetAsync("https://www.icanhazip.com/").Result.Content.ReadAsStringAsync().Result;

                        HttpResponseMessage response = client.GetAsync(String.Concat(audit.URL, "/full")).Result;
                        try { response.EnsureSuccessStatusCode(); }
                        catch {
                            try
                            {
                                Response.Clear();
                                response = client.GetAsync(audit.URL).Result;
                            }
                            catch
                            {
                                return BadRequest();
                            }
                        }

                        IPResult jsonResult = new IPResult();

                        try { jsonResult = response.Content.ReadFromJsonAsync<IPResult>().Result; }
                        catch (AggregateException ex) // jsonexceptions
                        {
                            return Ok(new IPResp { Pass = false, Score = 0, Comment = ex.Message });
                        }

                        if (jsonResult.IP != RealIP.TrimEnd('\n'))
                        {
                            return Ok(new IPResp { Pass = false, Score = 0, Comment = "Missing required variable - IP" });
                        }

                        int Score = 0;
                        foreach (var property in jsonResult.GetType().GetProperties())
                        {
                            if (property.GetValue(jsonResult, null) != null && property.GetValue(jsonResult, null) as string != string.Empty)
                            {
                                Score++;
                            }
                        }

                        audit.IPPass = true; audit.IPScore += Score;
                        _context.Update(audit);
                        _context.SaveChanges();

                        return Ok(new IPResp { Pass = true, Score = audit.IPScore});
                    }
                }
            }

        }
    }

    [ApiController]
    [Route("check/api/raw")]
    public class CheckRawAPI : ControllerBase
    {
        private readonly ILogger<CheckRawAPI> _logger;
        private readonly AppDbContext _context;

        public CheckRawAPI(ILogger<CheckRawAPI> logger, AppDbContext context)
        {
            _logger = logger;
            _context = context;
        }

        [HttpGet(Name = "CheckRawAPI")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(IPResp))]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public IActionResult Get(string Token)
        {
            var audit = _context.Audits.Where(u => u.Token == Token).FirstOrDefault();

            if (audit == null || audit.RawRan == true || audit.Finished == true || audit.CorsRan != true) { return BadRequest(); }
            else
            {
                audit.RawRan = true;
                _context.Update(audit);
                _context.SaveChanges();
                if (audit.OriginatingIP != Tool.GetIPHeaders(HttpContext.Request.Headers, HttpContext).IP
                    || audit.OriginatingUA != HttpContext.Request.Headers.UserAgent)
                {
                    return BadRequest();
                }
                else
                {
                    using HttpClient client = new HttpClient();
                    {
                        string RealIP = client.GetAsync("https://www.icanhazip.com/").Result.Content.ReadAsStringAsync().Result;

                        using HttpResponseMessage response = client.GetAsync(String.Concat(audit.URL, "/raw")).Result;
                        try { response.EnsureSuccessStatusCode(); }
                        catch { return BadRequest(); }

                        if (response.Content.ReadAsStringAsync().Result != RealIP.TrimEnd('\n'))
                        {
                            return Ok(new IPResp { Pass = false, Score = 0, Comment = "Response invalid" });
                        }

                        audit.RawPass = true; audit.IPScore += 1;
                        _context.Update(audit);
                        _context.SaveChanges();

                        return Ok(new IPResp { Pass = true, Score = audit.IPScore });
                    }
                }
            }
        
        }
    }

    [ApiController]
    [Route("check/api/lookup")]
    public class CheckLookupAPI : ControllerBase
    {
        private readonly ILogger<CheckLookupAPI> _logger;
        private readonly AppDbContext _context;

        public CheckLookupAPI(ILogger<CheckLookupAPI> logger, AppDbContext context)
        {
            _logger = logger;
            _context = context;
        }

        [HttpGet(Name = "CheckLookupAPI")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(IPResp))]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public IActionResult Get(string Token)
        {
            var audit = _context.Audits.Where(u => u.Token == Token).FirstOrDefault();

            if (audit == null || audit.LookupRan == true || audit.Finished == true || audit.CorsRan != true) { return BadRequest(); }
            else
            {
                audit.LookupRan = true;
                _context.Update(audit);
                _context.SaveChanges();
                if (audit.OriginatingIP != Tool.GetIPHeaders(HttpContext.Request.Headers, HttpContext).IP
                    || audit.OriginatingUA != HttpContext.Request.Headers.UserAgent)
                {
                    return BadRequest();
                }
                else
                {
                    using HttpClient client = new HttpClient();
                    {
                        using HttpResponseMessage response = client.GetAsync(String.Concat(audit.URL, "/lookup?ip=1.1.1.1")).Result;
                        try { response.EnsureSuccessStatusCode(); }
                        catch { return BadRequest(); }

                        IPResult jsonResult = new IPResult();

                        try { jsonResult = response.Content.ReadFromJsonAsync<IPResult>().Result; }
                        catch (AggregateException ex) // jsonexceptions
                        {
                            return Ok(new IPResp { Pass = false, Score = 0, Comment = ex.Message });
                        }

                        if (jsonResult.IP != "1.1.1.1")
                        {
                            return Ok(new IPResp { Pass = false, Score = 0, Comment = "Missing required variable - IP" });
                        }

                        using HttpResponseMessage responseFull = client.GetAsync(String.Concat(audit.URL, "/lookup/full?ip=1.1.1.1")).Result;
                        try { response.EnsureSuccessStatusCode(); }
                        catch { return BadRequest(); }

                        IPResult jsonResultFull = new IPResult();

                        try { jsonResult = responseFull.Content.ReadFromJsonAsync<IPResult>().Result; }
                        catch (AggregateException ex) // jsonexceptions
                        {
                            return Ok(new IPResp { Pass = false, Score = 0, Comment = ex.Message });
                        }

                        if (jsonResultFull.IP != "1.1.1.1")
                        {
                            return Ok(new IPResp { Pass = false, Score = 0, Comment = "Missing required variable on full endpoint - IP" });
                        }

                        int Score = 0;
                        foreach (var property in jsonResultFull.GetType().GetProperties())
                        {
                            if (property.GetValue(jsonResult, null) != null && property.GetValue(jsonResult, null) as string != string.Empty)
                            {
                                Score++;
                            }
                        }

                        audit.LookupPass = true; audit.IPScore += Score;
                        _context.Update(audit);
                        _context.SaveChanges();

                        return Ok(new IPResp { Pass = true, Score = audit.IPScore });
                    }
                }
            }

        }
    }

    [ApiController]
    [Route("check/api/lucky")]
    public class CheckLuckyAPI : ControllerBase
    {
        private readonly ILogger<CheckLuckyAPI> _logger;
        private readonly AppDbContext _context;

        public CheckLuckyAPI(ILogger<CheckLuckyAPI> logger, AppDbContext context)
        {
            _logger = logger;
            _context = context;
        }

        [HttpGet(Name = "CheckLuckyAPI")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(IPResp))]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public IActionResult Get(string Token)
        {
            var audit = _context.Audits.Where(u => u.Token == Token).FirstOrDefault();

            if (audit == null || audit.LuckyRan == true || audit.Finished == true || audit.CorsRan != true || audit.CorsRan != true) { return BadRequest(); }
            else
            {
                audit.LuckyRan = true;
                _context.Update(audit);
                _context.SaveChanges();
                if (audit.OriginatingIP != Tool.GetIPHeaders(HttpContext.Request.Headers, HttpContext).IP
                    || audit.OriginatingUA != HttpContext.Request.Headers.UserAgent)
                {
                    return BadRequest();
                }
                else
                {
                    using HttpClient client = new HttpClient();
                    {
                        string RealIP = client.GetAsync("https://v4.ipify.io/").Result.Content.ReadAsStringAsync().Result;

                        for (int i = 0; i < 512; i++)
                        {
                            using HttpResponseMessage response = client.GetAsync(String.Concat(audit.URL, "/imfeelinglucky")).Result;
                            try { response.EnsureSuccessStatusCode(); }
                            catch { return BadRequest(); }

                            IPResult jsonResult = new IPResult();

                            try { jsonResult = response.Content.ReadFromJsonAsync<IPResult>().Result; }
                            catch (AggregateException ex) // jsonexceptions
                            {
                                return Ok(new IPResp { Pass = false, Score = 0, Comment = ex.Message });
                            }

                            if (jsonResult.IP == null)
                            {
                                return Ok(new IPResp { Pass = false, Score = 0, Comment = "Missing required variable - IP" });
                            }

                            if (jsonResult.IP != RealIP)
                            {
                                audit.LuckyPass = true;
                                _context.Update(audit);
                                _context.SaveChanges();

                                return Ok(new IPResp { Pass = true, Score = 0 });
                            }

                        }
                        return Ok(new IPResp { Pass = false, Score = 0, Comment = "Did not return modified IP in 512 tries" });
                    }
                }
            }

        }
    }

    [ApiController]
    [Route("check/api/pass")]
    public class CheckPassAPI : ControllerBase
    {
        private readonly ILogger<CheckPassAPI> _logger;
        private readonly AppDbContext _context;

        public CheckPassAPI(ILogger<CheckPassAPI> logger, AppDbContext context)
        {
            _logger = logger;
            _context = context;
        }

        [HttpGet(Name = "CheckPassAPI")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(PassResp))]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public IActionResult Get(string Token)
        {
            var audit = _context.Audits.Where(u => u.Token == Token).FirstOrDefault();

            if (audit == null || audit.Finished == true) { return BadRequest(); }
            else
            {
                audit.Finished = true;
                _context.Update(audit);
                _context.SaveChanges();
                if (audit.OriginatingIP != Tool.GetIPHeaders(HttpContext.Request.Headers, HttpContext).IP
                    || audit.OriginatingUA != HttpContext.Request.Headers.UserAgent)
                {
                    return BadRequest();
                }
                else
                {
                    if (audit.IPPass && audit.RawPass && audit.LookupPass && audit.LuckyPass)
                    {
                        audit.PassResult = true;
                        audit.Passed = DateTime.Now;
                    }

                    if (audit.IPScore >= 20 && audit.PassResult == true)
                    {
                        audit.PassPlusResult = true;
                    }

                    Random rnd = new Random();
                    if (audit.PassPlusResult == true)
                    {
                        audit.PassID = rnd.Next(111111111, 999999999);
                        audit.PassID += 5000000000;
                    }
                    else if (audit.PassResult == true && audit.PassPlusResult == false)
                    {
                        audit.PassID = rnd.Next(111111111, 999999999);
                        audit.PassID += 1000000000;
                    }
                    audit.PassID = Math.Abs(audit.PassID);
                    _context.Update(audit);
                    _context.SaveChanges();

                    return Ok(new PassResp { Pass = audit.PassResult, PassPlus = audit.PassPlusResult, PassID = audit.PassID, Score = audit.IPScore });
                }
            }

        }
    }

    [ApiController]
    [Route("check/api/verify")]
    public class CheckVerifyAPI : ControllerBase
    {
        private readonly ILogger<CheckVerifyAPI> _logger;
        private readonly AppDbContext _context;

        public CheckVerifyAPI(ILogger<CheckVerifyAPI> logger, AppDbContext context)
        {
            _logger = logger;
            _context = context;
        }

        [HttpGet(Name = "CheckVerifyAPI")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(Audit))]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public IActionResult Get(long PassID)
        {
            if(PassID < 111111111)
            {
                return BadRequest();
            }

            var audit = _context.Audits.Where(u => u.PassID == PassID).FirstOrDefault();

            if (audit == null || audit.Finished != true) { return BadRequest(); }
            else
            {
                return Ok(audit);
            }

        }
    }
}