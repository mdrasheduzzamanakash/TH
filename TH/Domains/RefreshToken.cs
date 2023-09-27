namespace TH.Domains
{
    public class RefreshToken : BaseEntity
    {
        public string Token { get; set; } = string.Empty;
        public bool Status { get; set; }

        public string JwtId { get; set; } = string.Empty;

        public bool IsUsed { get; set; }

        public bool IsRevoked { get; set; }

        public DateTime ExpiryDate { get; set; }

        public string CustomerId { get; set; } = string.Empty;

        public string IdentityId { get; set; } = string.Empty;

    }
}
