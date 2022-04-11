using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Validators;
using Microsoft.Owin.Security.ActiveDirectory;
using Owin;
using System.Collections.Generic;
using System.Configuration;

namespace TodoListService
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit https://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            var issuer = string.Format(ConfigurationManager.AppSettings["ida:AADInstance"], ConfigurationManager.AppSettings["ida:TenantId"]);

            app.UseWindowsAzureActiveDirectoryBearerAuthentication(
                new WindowsAzureActiveDirectoryBearerAuthenticationOptions
                {
                    Tenant = ConfigurationManager.AppSettings["ida:Tenant"],
                    //We set SaveSigninToken to true, to be able to retrieve the bearer token using the code: ClaimsPrincipal.Current.Identities.First().BootstrapContext
                    //This flag is mandatory for this flow to work
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        SaveSigninToken = true,
                        ValidAudiences = new List<string> { ConfigurationManager.AppSettings["ida:Audience"], ConfigurationManager.AppSettings["ida:ClientId"] },
                        IssuerValidator = AadIssuerValidator.GetAadIssuerValidator(issuer).Validate
                    }
                });
        }
    }
}