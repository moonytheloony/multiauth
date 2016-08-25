namespace MultiAuthApp.Controllers
{
    #region

    using System.Linq;
    using System.Web;
    using System.Web.Mvc;

    using Microsoft.Owin.Security;

    #endregion

    public class AccountController : Controller
    {
        #region Public Methods and Operators

        public void EmployeeSignIn()
        {
            if (!this.Request.IsAuthenticated)
            {
                this.HttpContext.GetOwinContext().Authentication.Challenge(new AuthenticationProperties { RedirectUri = "/" }, Startup.B2EEmployeeSignInPolicyId);
            }
        }

        public void Profile()
        {
            if (this.Request.IsAuthenticated)
            {
                this.HttpContext.GetOwinContext().Authentication.Challenge(new AuthenticationProperties { RedirectUri = "/" }, Startup.ProfilePolicyId);
            }
        }

        public void SignIn()
        {
            if (!this.Request.IsAuthenticated)
            {
                // To execute a policy, you simply need to trigger an OWIN challenge.
                // You can indicate which policy to use by specifying the policy id as the AuthenticationType
                this.HttpContext.GetOwinContext().Authentication.Challenge(new AuthenticationProperties { RedirectUri = "/" }, Startup.SignInPolicyId);
            }
        }

        public void SignOut()
        {
            // To sign out the user, you should issue an OpenIDConnect sign out request.
            if (this.Request.IsAuthenticated)
            {
                var authTypes = this.HttpContext.GetOwinContext().Authentication.GetAuthenticationTypes();
                this.HttpContext.GetOwinContext().Authentication.SignOut(authTypes.Select(t => t.AuthenticationType).ToArray());
                this.Request.GetOwinContext().Authentication.GetAuthenticationTypes();
            }
        }

        public void SignUp()
        {
            if (!this.Request.IsAuthenticated)
            {
                this.HttpContext.GetOwinContext().Authentication.Challenge(new AuthenticationProperties { RedirectUri = "/" }, Startup.SignUpPolicyId);
            }
        }

        #endregion
    }
}