namespace TH.Configurations
{
    public class Smtp2GoConfig
    {
        public string SmtpServer { get; set; }
        public int SmtpPort { get; set; }
        public string SmtpUsername { get; set; }
        public string SmtpPassword { get; set;}
        public string From { get; set; }
        
        public bool EnableSSL { get; set; }
        
    }
}
