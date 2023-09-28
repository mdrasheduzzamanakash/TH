using System.Net.Mail;
using System.Net;
using TH.Configurations;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Mvc;
using TH.Domains;

namespace TH.Services.ThirdPartyServices
{
    public class EmailSmtp2GoService : IEmailService
    {
        #region Fields
        private readonly Smtp2GoConfig _smtp2GoConfig;
        private readonly ILogService _logService;
        #endregion

        #region Ctor
        public EmailSmtp2GoService(IOptionsMonitor<Smtp2GoConfig> optionMonitor,
            ILogService logService)
        {
            _smtp2GoConfig = optionMonitor.CurrentValue;
            _logService = logService;
        }

        #endregion

        #region Methods 

        public async Task<bool> SendAccountVerificationMailAsync(string to, string link, Dictionary<string, string> additionalData)
        {
            string mailSubject = "Verification for " + THDefaults.AppName;
            string additionalText = "Thank you for joining " + THDefaults.AppName + " ! Please verify your email to complete the registration process. You will be a verified user of the site and will be able to use every features.";
            
            string mailBody = $@"Dear {additionalData["Name"]},

                    {additionalText}

                    Click the following button or link to verify your email:
                    <a href=""{link}""><button style=""background-color: #4CAF50; color: white; padding: 10px 20px; text-align: center; text-decoration: none; display: inline-block; font-size: 16px; margin: 4px 2px; cursor: pointer;"">Activate</button></a>
                    Or pasete the link in url bar of any browser. <br>
                    <a href=""{link}"">{link}</a>";

            try
            {
                using (var message = new MailMessage())
                {
                    message.From = new MailAddress(_smtp2GoConfig.From); // Replace with your sender email address
                    message.To.Add(to);
                    message.Subject = mailSubject;
                    message.Body = mailBody;
                    message.IsBodyHtml = true;

                    using (var smtpClient = new SmtpClient(_smtp2GoConfig.SmtpServer, _smtp2GoConfig.SmtpPort))
                    {
                        smtpClient.EnableSsl = _smtp2GoConfig.EnableSSL;
                        smtpClient.Credentials = new NetworkCredential(_smtp2GoConfig.SmtpUsername, _smtp2GoConfig.SmtpPassword);
                        await smtpClient.SendMailAsync(message);
                    }

                    var _ = await _logService.InsertAsync(new Log
                    {
                        Message = "Account verification mail sent",
                        Description = message.ToString() ?? "",
                        Origin = "Namespace : " + this.GetType().Namespace + ", Class : " + this.GetType().Name,
                        Tag = THDefaults.Fluid,
                        Type = THDefaults.Information
                    });

                    return true;
                }
            }
            catch (Exception ex)
            {
                var _ = await _logService.InsertAsync(new Log
                {
                    Message = ex.Message,
                    Description = ex.ToString() ?? "",
                    Origin = "Namespace : " + this.GetType().Namespace + ", Class : " + this.GetType().Name,
                    Tag = THDefaults.Urgent,
                    Type = THDefaults.Error
                });

                return false;
            }
        }

        public async Task<bool> PasswordResetMailAsync(string to, string link, Dictionary<string, string> additionalData)
        {
            string mailSubject = "Password reset for " + THDefaults.AppName;
            string additionalText = "Thank you for joining " + THDefaults.AppName + " ! Please click the button or link below to reset password.";

            string mailBody = $@"Dear {additionalData["Name"]},

                    {additionalText}
:
                    <a href=""{link}""><button style=""background-color: #4CAF50; color: white; padding: 10px 20px; text-align: center; text-decoration: none; display: inline-block; font-size: 16px; margin: 4px 2px; cursor: pointer;"">Activate</button></a>
                    Or pasete the link in url bar of any browser. <br>
                    <a href=""{link}"">{link}</a>";

            try
            {
                using (var message = new MailMessage())
                {
                    message.From = new MailAddress(_smtp2GoConfig.From); // Replace with your sender email address
                    message.To.Add(to);
                    message.Subject = mailSubject;
                    message.Body = mailBody;
                    message.IsBodyHtml = true;

                    using (var smtpClient = new SmtpClient(_smtp2GoConfig.SmtpServer, _smtp2GoConfig.SmtpPort))
                    {
                        smtpClient.EnableSsl = _smtp2GoConfig.EnableSSL;
                        smtpClient.Credentials = new NetworkCredential(_smtp2GoConfig.SmtpUsername, _smtp2GoConfig.SmtpPassword);
                        await smtpClient.SendMailAsync(message);
                    }

                    var _ = await _logService.InsertAsync(new Log
                    {
                        Message = "Password reset mail sent",
                        Description = message.ToString() ?? "",
                        Origin = "Namespace : " + this.GetType().Namespace + ", Class : " + this.GetType().Name,
                        Tag = THDefaults.Fluid,
                        Type = THDefaults.Information
                    });

                    return true;
                }
            }
            catch (Exception ex)
            {
                var _ = await _logService.InsertAsync(new Log
                {
                    Message = ex.Message,
                    Description = ex.ToString() ?? "",
                    Origin = "Namespace : " + this.GetType().Namespace + ", Class : " + this.GetType().Name,
                    Tag = THDefaults.Urgent,
                    Type = THDefaults.Error
                });

                return false;
            }
        }


        #endregion
    }
}
