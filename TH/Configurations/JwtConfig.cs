namespace TH.Configurations
{
    public class JwtConfig
    {
        public string Secret { get; set; }
        public TimeSpan ExpiryTimeFrame { get; set; }
        public string ValidAudience { get; set; }
        public string ValidIssuer { get; set; }

    }
}
