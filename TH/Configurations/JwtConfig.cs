namespace TH.Configurations
{
    public class JwtConfig
    {
        public string Secret { get; set; } = string.Empty;
        public TimeSpan ExpiryTimeFrame { get; set; }
        public string ValidAudience { get; set; } = string.Empty;
        public string ValidIssuer { get; set; } = string.Empty;

    }
}
