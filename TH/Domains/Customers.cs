namespace TH.Domains
{
    public class Customers : BaseEntity
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string IdentityId { get; set; } = string.Empty;
        public string OnRole { get; set; } = string.Empty;

    }
}
