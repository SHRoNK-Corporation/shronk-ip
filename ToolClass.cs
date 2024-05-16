using LiteDB;
using MaxMind.GeoIP2;

namespace shronkip
{
    public static class Tool
    {
        public static LiteDatabase db = new LiteDatabase(@"AuditDB.db");
        public static ILiteCollection<Audit> col = db.GetCollection<Audit>("Audits");

        public static IPLookup GetIPHeaders(IHeaderDictionary headers, HttpContext context)
        {
            string ip, source;

            if ((string) headers["CF-Connecting-IP"] != null)
            {
                ip =  headers["CF-Connecting-IP"];
                source = "Cloudflare";
            }
            else if ((string) headers["Forwarded"] != null)
            {
                ip = headers["Forwarded"];
                source = "Forwarded";
            }
            else if ((string) headers["X-Forwarded-For"] != null)
            {
                ip = headers["X-Forwarded-For"];
                source = "X-Forwarded-For";
            }
            else
            {
                ip = context.Connection.RemoteIpAddress.MapToIPv4().ToString();
                source = "Direct IP";
            }

            return new IPLookup
            {
                IP = ip,
                Source = source
            };
        }

        public static IPResult LuckyLookup(IPLookup client, ILogger _logger, int threshhold)
        {
            string[] SplitIP = client.IP.Split(".");

            Random rnd = new Random();

            for (int i = 0; i < SplitIP.Length; i++)
            {
                if (SplitIP[i] == "255")
                {
                    SplitIP[i] = "256";
                    _logger.LogInformation("Pushing up octet");
                }
                else if (SplitIP[i] == "1" && client.IP != "1.1.1.1")
                {
                    SplitIP[i] = "0";
                    _logger.LogInformation("Pulling down octet");
                }
                else
                {
                    int chance = rnd.Next(200);
                    if (chance > threshhold)
                    {
                        SplitIP[i] = rnd.Next(255).ToString();
                        _logger.LogInformation("Randomizing octet");

                    }
                }
            }

            IPResult result = Tool.DbLookup(client, _logger);
            result.IP = $"{SplitIP[0]}.{SplitIP[1]}.{SplitIP[2]}.{SplitIP[3]}";

            return result;
        }

        public static IPResult DbLookup(IPLookup lookup, ILogger _logger)
        {
            var CityReader = new DatabaseReader("dbip-city-lite-2024-04.mmdb");
            var ASNReader = new DatabaseReader("dbip-asn-lite-2024-04.mmdb");

            if (lookup.IP == "81.102.249.156")
            {
                return new IPResult
                {
                    IP = "81.102.249.156",
                    City = "Kippax (retirement village)",
                    Country = "United Kingdom",
                    BrexitRequired = false,
                    CountryCode = "GB",
                    ASN = 5089,
                    ISP = "SHRoNK Media",
                    Legalese = "IP Geolocation by DB-IP. CC BY 4.0 DEED https://db-ip.com",
                    Source = "Me"
                };
            }

            try
            {
                var CityResult = CityReader.City(lookup.IP);
                var ASNResult = ASNReader.Asn(lookup.IP);

                return new IPResult
                {
                    IP = lookup.IP,
                    City = CityResult.City.Name,
                    Country = CityResult.Country.Name,
                    BrexitRequired = CityResult.Country.IsInEuropeanUnion,
                    CountryCode = CityResult.Country.IsoCode,
                    ASN = ASNResult.AutonomousSystemNumber,
                    ISP = ASNResult.AutonomousSystemOrganization,
                    Legalese = "IP Geolocation by DB-IP. CC BY 4.0 DEED https://db-ip.com",
                    Source = lookup.Source

                };
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error reading database");

                return new IPResult
                {
                    IP = lookup.IP,
                    City = "Geolocation Failed",
                    Country = "Geolocation Failed",
                    BrexitRequired = false,
                    CountryCode = "Geolocation Failed",
                    ASN = 000000,
                    ISP = "Geolocation Failed",
                    Legalese = "IP Geolocation by DB-IP. CC BY 4.0 DEED https://db-ip.com"
                };
            }

        }
    }
}
