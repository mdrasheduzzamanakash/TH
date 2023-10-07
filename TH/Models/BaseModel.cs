namespace TH.Models
{
    public class BaseModel
    {
        public string Id { get; set; } = string.Empty;
        public BaseModel()
        {
            CustomProperties = new Dictionary<string, string>();
        }
        public Dictionary<string, string> CustomProperties { get; set; }
    }
}
