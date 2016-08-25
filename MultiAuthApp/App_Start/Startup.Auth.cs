namespace MultiAuthApp
{
    #region

    using System;
    using System.Configuration;
    using System.IdentityModel.Tokens;
    using System.Threading.Tasks;

    using Microsoft.AspNet.Identity;
    using Microsoft.AspNet.Identity.EntityFramework;
    using Microsoft.IdentityModel.Protocols;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Cookies;
    using Microsoft.Owin.Security.Notifications;
    using Microsoft.Owin.Security.OpenIdConnect;

    using Owin;

    #endregion

    public partial class Startup
    {
        #region Static Fields

        public static string ProfilePolicyId = ConfigurationManager.AppSettings["ida:UserProfilePolicyId"];

        public static string SignInPolicyId = ConfigurationManager.AppSettings["ida:SignInPolicyId"];

        public static string B2EEmployeeSignInPolicyId = ConfigurationManager.AppSettings["ida:B2EEmployeeSignInPolicyId"];

        // B2C policy identifiers
        public static string SignUpPolicyId = ConfigurationManager.AppSettings["ida:SignUpPolicyId"];

        private static readonly string aadInstance = ConfigurationManager.AppSettings["ida:AadInstance"];

        private static readonly string b2eAadInstance = ConfigurationManager.AppSettings["ida:B2EAadInstance"];

        private static readonly string b2eClientId = ConfigurationManager.AppSettings["ida:B2EClientId"];

        private static string b2eTenant = ConfigurationManager.AppSettings["ida:B2ETenant"];

        // App config settings
        private static readonly string clientId = ConfigurationManager.AppSettings["ida:ClientId"];

        private static readonly string redirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];

        private static readonly string tenant = ConfigurationManager.AppSettings["ida:Tenant"];

        #endregion

        #region Public Properties

        public static Func<RoleManager<IdentityRole>> RoleManagerFactory { get; set; }

        #endregion

        #region Public Methods and Operators

        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());
            // Added dummy middleware to inspect values.
            app.Use(async (context, next) => { await next.Invoke(); });

            // Configure OpenID Connect middleware for each policy
            app.UseOpenIdConnectAuthentication(this.CreateOptionsFromPolicy(SignUpPolicyId));
            app.Use(async (context, next) => { await next.Invoke(); });

            app.UseOpenIdConnectAuthentication(this.CreateOptionsFromPolicy(ProfilePolicyId));
            app.Use(async (context, next) => { await next.Invoke(); });

            app.UseOpenIdConnectAuthentication(this.CreateOptionsFromPolicy(SignInPolicyId));
            app.Use(async (context, next) => { await next.Invoke(); });

            //Configure OpenID Connect middleware for B2E policy
            app.UseOpenIdConnectAuthentication(this.CreateB2EOptions());
        }

        #endregion

        #region Methods

        // Used for avoiding yellow-screen-of-death
        private Task AuthenticationFailed(
            AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
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

        private OpenIdConnectAuthenticationOptions CreateB2EOptions()
        {
            return new OpenIdConnectAuthenticationOptions
            {
                Authority = string.Format(b2eAadInstance, "common"),
                ClientId = b2eClientId,
                RedirectUri = redirectUri,
                PostLogoutRedirectUri = redirectUri,
                Notifications =
                        new OpenIdConnectAuthenticationNotifications { AuthenticationFailed = this.AuthenticationFailed },
                TokenValidationParameters = new TokenValidationParameters { ValidateIssuer = false },
                AuthenticationType = "OpenIdConnect-B2E"
            };
        }

        private OpenIdConnectAuthenticationOptions CreateOptionsFromPolicy(string policy)
        {
            return new OpenIdConnectAuthenticationOptions
            {
                // For each policy, give OWIN the policy-specific metadata address, and
                // set the authentication type to the id of the policy
                MetadataAddress = string.Format(aadInstance, tenant, policy),
                AuthenticationType = policy,

                // These are standard OpenID Connect parameters, with values pulled from web.config
                ClientId = clientId,
                RedirectUri = redirectUri,
                PostLogoutRedirectUri = redirectUri,
                Notifications =
                        new OpenIdConnectAuthenticationNotifications { AuthenticationFailed = this.AuthenticationFailed },
                Scope = "openid",
                ResponseType = "id_token",

                // This piece is optional - it is used for displaying the user's name in the navigation bar.
                TokenValidationParameters = new TokenValidationParameters { NameClaimType = "name" }
            };
        }

        #endregion
    }
}