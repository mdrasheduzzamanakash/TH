namespace TH.Models
{
    public class BaseModel
    {
        public int Id { get; set; }
        public BaseModel()
        {
            CustomProperties = new Dictionary<string, string>();
        }
        public Dictionary<string, string> CustomProperties { get; set; }
    }
}
