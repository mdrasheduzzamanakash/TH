namespace TH.Domains
{
    public class Customer : BaseEntity
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string IdentityId { get; set; } = string.Empty;
        public string OnRole { get; set; } = string.Empty;

    }
}
