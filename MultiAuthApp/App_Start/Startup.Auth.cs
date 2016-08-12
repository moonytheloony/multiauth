using System;
using System.Configuration;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using MultiAuthApp.Models;
using Owin;
using Microsoft.AspNet.Identity.EntityFramework;

namespace MultiAuthApp
{
    public partial class Startup
    {
        public static Func<RoleManager<IdentityRole>> RoleManagerFactory { get; set; }

        // App config settings
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string b2eClientId = ConfigurationManager.AppSettings["ida:B2EClientId"];
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AadInstance"];
        private static string b2eAadInstance = ConfigurationManager.AppSettings["ida:B2EAadInstance"];
        private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string b2eTenant = ConfigurationManager.AppSettings["ida:B2ETenant"];
        private static string redirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];

        // B2C policy identifiers
        public static string SignUpPolicyId = ConfigurationManager.AppSettings["ida:SignUpPolicyId"];
        public static string SignInPolicyId = ConfigurationManager.AppSettings["ida:SignInPolicyId"];
        public static string ProfilePolicyId = ConfigurationManager.AppSettings["ida:UserProfilePolicyId"];
        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            // Configure OpenID Connect middleware for each policy
            app.UseOpenIdConnectAuthentication(CreateOptionsFromPolicy(SignUpPolicyId));
            app.UseOpenIdConnectAuthentication(CreateOptionsFromPolicy(ProfilePolicyId));
            app.UseOpenIdConnectAuthentication(CreateOptionsFromPolicy(SignInPolicyId));

            //Configure OpenID Connect middlewaree for B2E policy
            app.UseOpenIdConnectAuthentication(CreateB2EOptions());

            //Setup role manager factory
            RoleManagerFactory = () => new RoleManager<IdentityRole>(new RoleStore<IdentityRole>());
        }

        // Used for avoiding yellow-screen-of-death
        private Task AuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();
            if (notification.Exception.Message == "access_denied")
            {
                notification.Response.Redirect("/");
            }
            else
            {
                notification.Response.Redirect("/Home/Error?message=" + notification.Exception.Message);
            }

            return Task.FromResult(0);
        }

        private OpenIdConnectAuthenticationOptions CreateOptionsFromPolicy(string policy)
        {
            return new OpenIdConnectAuthenticationOptions
            {
                // For each policy, give OWIN the policy-specific metadata address, and
                // set the authentication type to the id of the policy
                MetadataAddress = String.Format(aadInstance, tenant, policy),
                AuthenticationType = policy,

                // These are standard OpenID Connect parameters, with values pulled from web.config
                ClientId = clientId,
                RedirectUri = redirectUri,
                PostLogoutRedirectUri = redirectUri,
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthenticationFailed = AuthenticationFailed,
                },
                Scope = "openid",
                ResponseType = "id_token",

                // This piece is optional - it is used for displaying the user's name in the navigation bar.
                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                },
            };
        }

        private OpenIdConnectAuthenticationOptions CreateB2EOptions()
        {
            return new OpenIdConnectAuthenticationOptions
            {
                Authority = string.Format(b2eAadInstance, "common"),
                ClientId = b2eClientId,
                RedirectUri = redirectUri,
                PostLogoutRedirectUri = redirectUri,
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthenticationFailed = AuthenticationFailed,
                },

                TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                },

                AuthenticationType = "OpenIdConnect-B2E",
            };
        }

    }
}