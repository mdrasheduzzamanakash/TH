namespace TH.Services.ThirdPartyServices
{
    public interface IEmailService
    {
        Task<bool> SendAccountVerificationMailAsync(string to, string link, Dictionary<string, string> additionalData);
        Task<bool> PasswordResetMailAsync(string to, string link, Dictionary<string, string> additionalData);
    }
}
