using Microsoft.AspNetCore.Identity.UI.Services;
using System.Net;
using System.Net.Mail;

namespace UserManagement.Service
{
    public class EmailSender : IEmailSender
    {
        public EmailSender()
        {

        }

        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            // Here you only need to change fromMail "Your Email" and fromPassword "Your Password"
            string fromMail = "ali.hamza@tm.iq";
            string fromPassword = "********";

            MailMessage message = new MailMessage();
            message.From = new MailAddress(fromMail);
            message.Subject = subject;
            message.To.Add(new MailAddress(email));
            message.Body = "<html><body> " + htmlMessage + " </body></html>";
            message.IsBodyHtml = true;

            var smtpClient = new SmtpClient("smtp.gmail.com")
            {
                // Your Email Provider Configurations
                Port = 587,
                Credentials = new NetworkCredential(fromMail, fromPassword),

                // always enable ssl
                EnableSsl = true,
            };

            // Send Email
            smtpClient.Send(message);
            return Task.CompletedTask;
        }
    }
}
