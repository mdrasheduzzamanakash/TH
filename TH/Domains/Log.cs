namespace TH.Domains
{
    public class Log : BaseEntity
    {
        public string Message { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string Origin { get; set; } = string.Empty;
        public string Tag { get; set; } = string.Empty;
    }
}
