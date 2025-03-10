﻿using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;

namespace shronkip
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        public DbSet<Audit> Audits { get; set; }
    }

    public class Audit
    {
        [JsonIgnore] public int Id { get; set; }
        [JsonIgnore] public string Token { get; set; } = System.Guid.NewGuid().ToString();
        public DateTime Created { get; set; } = DateTime.Now;
        public DateTime Passed { get; set; } = DateTime.UnixEpoch;
        [JsonIgnore] public string OriginatingIP { get; set; } = string.Empty;
        [JsonIgnore] public string OriginatingUA { get; set; } = string.Empty;
        public string Server { get; set; } = string.Empty;
        public string URL { get; set; } = string.Empty;
        public bool ConnectPass { get; set; } = false;
        public bool CorsPass { get; set; } = false;
        public bool CorsRan { get; set; } = false;
        public bool IPPass { get; set; } = false;
        public int IPScore { get; set; } = 0;
        public bool IPRan { get; set; } = false;
        public bool RawPass { get; set; } = false;
        public bool RawRan { get; set; } = false;
        public bool LookupPass { get; set; } = false;
        public bool LookupRan { get; set; } = false;
        public bool LuckyPass { get; set; } = false; 
        public bool LuckyRan { get; set; } = false;
        public bool PassResult { get; set; } = false;
        public bool PassPlusResult { get; set; } = false;
        public bool Finished { get; set; } = false;
        public long PassID { get; set; } = 0000000000;
    }

    public class AuthReq
    {
        public string URL { get; set; } = string.Empty;
    }

    public class AuthResp
    {
        public string Token { get; set; } = string.Empty;
    }

    public class CertReq
    {
        public string Token { get; set; } = string.Empty;
    }

    public class CorsResp
    {
        public string Message {  get; set; } = string.Empty;
        public bool ConnectPass { get; set; }
        public bool CorsPass { get; set; }
    }

    public class IPResp
    {
        public bool Pass { get; set; }
        public int Score { get; set; } = 0;
        public string Comment { get; set; } = string.Empty;
    }

    public class PassResp
    {
        public bool Pass { get; set; } = false;
        public bool PassPlus { get; set; } = false;
        public int Score { get; set; } = 0;
        public long PassID { get; set; } = 0;
    }
}

