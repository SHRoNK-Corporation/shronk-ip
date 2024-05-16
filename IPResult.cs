namespace shronkip
{
    public class IPResult
    {
        public string? IP {  get; set; }
        public string? City { get; set; }
        public string? Country { get; set; }
        public string? CountryCode { get; set; }
        public bool? BrexitRequired { get; set; }
        public long? ASN { get; set; }
        public string? ISP { get; set; }
        public string? Legalese { get; set; }
        public string? Source { get; set; }
        public string? blank { get; set; }
    }

    public class IPLookup
    {
        public string? IP { get; set; }
        public string? Source { get; set; }
    }

    public class InfoResp
    {
        public string Server { get; set; } = string.Empty;
        public string Maintainer { get; set; } = string.Empty;
        public int PassID { get; set; } = 0;

    }
}
